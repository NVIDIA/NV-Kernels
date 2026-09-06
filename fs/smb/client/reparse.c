// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Paulo Alcantara <pc@manguebit.com>
 */

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include "cifsglob.h"
#include "smb2proto.h"
#include "cifsproto.h"
#include "cifs_unicode.h"
#include "cifs_debug.h"
#include "reparse.h"

int smb2_create_reparse_symlink(const unsigned int xid, struct inode *inode,
				struct dentry *dentry, struct cifs_tcon *tcon,
				const char *full_path, const char *symname)
{
	struct reparse_symlink_data_buffer *buf = NULL;
	struct cifs_open_info_data data;
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct inode *new;
	struct kvec iov;
	__le16 *path;
	char *sym, sep = CIFS_DIR_SEP(cifs_sb);
	u16 len, plen;
	int rc = 0;

	if (strlen(symname) > REPARSE_SYM_PATH_MAX)
		return -ENAMETOOLONG;

	sym = kstrdup(symname, GFP_KERNEL);
	if (!sym)
		return -ENOMEM;

	data = (struct cifs_open_info_data) {
		.reparse_point = true,
		.reparse = { .tag = IO_REPARSE_TAG_SYMLINK, },
		.symlink_target = sym,
	};

	convert_delimiter(sym, sep);
	path = cifs_convert_path_to_utf16(sym, cifs_sb);
	if (!path) {
		rc = -ENOMEM;
		goto out;
	}

	plen = 2 * UniStrnlen((wchar_t *)path, REPARSE_SYM_PATH_MAX);
	len = sizeof(*buf) + plen * 2;
	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	buf->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	buf->ReparseDataLength = cpu_to_le16(len - sizeof(struct reparse_data_buffer));
	buf->SubstituteNameOffset = cpu_to_le16(plen);
	buf->SubstituteNameLength = cpu_to_le16(plen);
	memcpy(&buf->PathBuffer[plen], path, plen);
	buf->PrintNameOffset = 0;
	buf->PrintNameLength = cpu_to_le16(plen);
	memcpy(buf->PathBuffer, path, plen);
	buf->Flags = cpu_to_le32(*symname != '/' ? SYMLINK_FLAG_RELATIVE : 0);
	if (*sym != sep)
		buf->Flags = cpu_to_le32(SYMLINK_FLAG_RELATIVE);

	convert_delimiter(sym, '/');
	iov.iov_base = buf;
	iov.iov_len = len;
	new = smb2_get_reparse_inode(&data, inode->i_sb, xid,
				     tcon, full_path, &iov);
	if (!IS_ERR(new))
		d_instantiate(dentry, new);
	else
		rc = PTR_ERR(new);
out:
	kfree(path);
	cifs_free_open_info(&data);
	kfree(buf);
	return rc;
}

static int nfs_set_reparse_buf(struct reparse_posix_data *buf,
			       mode_t mode, dev_t dev,
			       struct kvec *iov)
{
	u64 type;
	u16 len, dlen;

	len = sizeof(*buf);

	switch ((type = reparse_mode_nfs_type(mode))) {
	case NFS_SPECFILE_BLK:
	case NFS_SPECFILE_CHR:
		dlen = sizeof(__le64);
		break;
	case NFS_SPECFILE_FIFO:
	case NFS_SPECFILE_SOCK:
		dlen = 0;
		break;
	default:
		return -EOPNOTSUPP;
	}

	buf->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_NFS);
	buf->Reserved = 0;
	buf->InodeType = cpu_to_le64(type);
	buf->ReparseDataLength = cpu_to_le16(len + dlen -
					     sizeof(struct reparse_data_buffer));
	*(__le64 *)buf->DataBuffer = cpu_to_le64(((u64)MINOR(dev) << 32) |
						 MAJOR(dev));
	iov->iov_base = buf;
	iov->iov_len = len + dlen;
	return 0;
}

int smb2_make_nfs_node(unsigned int xid, struct inode *inode,
		       struct dentry *dentry, struct cifs_tcon *tcon,
		       const char *full_path, umode_t mode, dev_t dev)
{
	struct cifs_open_info_data data;
	struct reparse_posix_data *p;
	struct inode *new;
	struct kvec iov;
	__u8 buf[sizeof(*p) + sizeof(__le64)];
	int rc;

	p = (struct reparse_posix_data *)buf;
	rc = nfs_set_reparse_buf(p, mode, dev, &iov);
	if (rc)
		return rc;

	data = (struct cifs_open_info_data) {
		.reparse_point = true,
		.reparse = { .tag = IO_REPARSE_TAG_NFS, .posix = p, },
	};

	new = smb2_get_reparse_inode(&data, inode->i_sb, xid,
				     tcon, full_path, &iov);
	if (!IS_ERR(new))
		d_instantiate(dentry, new);
	else
		rc = PTR_ERR(new);
	cifs_free_open_info(&data);
	return rc;
}

/* See MS-FSCC 2.1.2.6 for the 'NFS' style reparse tags */
static int parse_reparse_posix(struct reparse_posix_data *buf,
			       struct cifs_sb_info *cifs_sb,
			       struct cifs_open_info_data *data)
{
	unsigned int len;
	u64 type;

	len = le16_to_cpu(buf->ReparseDataLength);
	if (len < sizeof(buf->InodeType)) {
		cifs_dbg(VFS, "srv returned malformed nfs buffer\n");
		return -EIO;
	}

	len -= sizeof(buf->InodeType);

	switch ((type = le64_to_cpu(buf->InodeType))) {
	case NFS_SPECFILE_LNK:
		if (len == 0 || (len % 2)) {
			cifs_dbg(VFS, "srv returned malformed nfs symlink buffer\n");
			return -EIO;
		}
		/*
		 * Check that buffer does not contain UTF-16 null codepoint
		 * because Linux cannot process symlink with null byte.
		 */
		if (UniStrnlen((wchar_t *)buf->DataBuffer, len/2) != len/2) {
			cifs_dbg(VFS, "srv returned null byte in nfs symlink target location\n");
			return -EIO;
		}
		data->symlink_target = cifs_strndup_from_utf16(buf->DataBuffer,
							       len, true,
							       cifs_sb->local_nls);
		if (!data->symlink_target)
			return -ENOMEM;
		cifs_dbg(FYI, "%s: target path: %s\n",
			 __func__, data->symlink_target);
		break;
	case NFS_SPECFILE_CHR:
	case NFS_SPECFILE_BLK:
		/* DataBuffer for block and char devices contains two 32-bit numbers */
		if (len != 8) {
			cifs_dbg(VFS, "srv returned malformed nfs buffer for type: 0x%llx\n", type);
			return -EIO;
		}
		break;
	case NFS_SPECFILE_FIFO:
	case NFS_SPECFILE_SOCK:
		/* DataBuffer for fifos and sockets is empty */
		if (len != 0) {
			cifs_dbg(VFS, "srv returned malformed nfs buffer for type: 0x%llx\n", type);
			return -EIO;
		}
		break;
	default:
		cifs_dbg(VFS, "%s: unhandled inode type: 0x%llx\n",
			 __func__, type);
		return -EOPNOTSUPP;
	}
	return 0;
}

int smb2_parse_native_symlink(char **target, const char *buf, unsigned int len,
			      bool unicode, bool relative,
			      const char *full_path,
			      struct cifs_sb_info *cifs_sb)
{
	char sep = CIFS_DIR_SEP(cifs_sb);
	char *linux_target = NULL;
	char *smb_target = NULL;
	int levels;
	int rc;
	int i;

	smb_target = cifs_strndup_from_utf16(buf, len, unicode, cifs_sb->local_nls);
	if (!smb_target) {
		rc = -ENOMEM;
		goto out;
	}

	if (smb_target[0] == sep && relative) {
		/*
		 * This is a relative SMB symlink from the top of the share,
		 * which is the top level directory of the Linux mount point.
		 * Linux does not support such relative symlinks, so convert
		 * it to the relative symlink from the current directory.
		 * full_path is the SMB path to the symlink (from which is
		 * extracted current directory) and smb_target is the SMB path
		 * where symlink points, therefore full_path must always be on
		 * the SMB share.
		 */
		int smb_target_len = strlen(smb_target)+1;
		levels = 0;
		for (i = 1; full_path[i]; i++) { /* i=1 to skip leading sep */
			if (full_path[i] == sep)
				levels++;
		}
		linux_target = kmalloc(levels*3 + smb_target_len, GFP_KERNEL);
		if (!linux_target) {
			rc = -ENOMEM;
			goto out;
		}
		for (i = 0; i < levels; i++) {
			linux_target[i*3 + 0] = '.';
			linux_target[i*3 + 1] = '.';
			linux_target[i*3 + 2] = sep;
		}
		/* +1 to skip leading sep */
		memcpy(linux_target + levels*3, smb_target+1, smb_target_len-1);
	} else {
		linux_target = smb_target;
		smb_target = NULL;
	}

	if (sep == '\\')
		convert_delimiter(linux_target, '/');

	rc = 0;
	*target = linux_target;

	cifs_dbg(FYI, "%s: symlink target: %s\n", __func__, *target);

out:
	if (rc != 0)
		kfree(linux_target);
	kfree(smb_target);
	return rc;
}

static int parse_reparse_symlink(struct reparse_symlink_data_buffer *sym,
				 u32 plen, bool unicode,
				 struct cifs_sb_info *cifs_sb,
				 const char *full_path,
				 struct cifs_open_info_data *data)
{
	unsigned int len;
	unsigned int offs;

	/* We handle Symbolic Link reparse tag here. See: MS-FSCC 2.1.2.4 */

	offs = le16_to_cpu(sym->SubstituteNameOffset);
	len = le16_to_cpu(sym->SubstituteNameLength);
	if (offs + 20 > plen || offs + len + 20 > plen) {
		cifs_dbg(VFS, "srv returned malformed symlink buffer\n");
		return -EIO;
	}

	return smb2_parse_native_symlink(&data->symlink_target,
					 sym->PathBuffer + offs,
					 len,
					 unicode,
					 le32_to_cpu(sym->Flags) & SYMLINK_FLAG_RELATIVE,
					 full_path,
					 cifs_sb);
}

int parse_reparse_point(struct reparse_data_buffer *buf,
			u32 plen, struct cifs_sb_info *cifs_sb,
			const char *full_path,
			bool unicode, struct cifs_open_info_data *data)
{
	data->reparse.buf = buf;

	/* See MS-FSCC 2.1.2 */
	switch (le32_to_cpu(buf->ReparseTag)) {
	case IO_REPARSE_TAG_NFS:
		return parse_reparse_posix((struct reparse_posix_data *)buf,
					   cifs_sb, data);
	case IO_REPARSE_TAG_SYMLINK:
		return parse_reparse_symlink(
			(struct reparse_symlink_data_buffer *)buf,
			plen, unicode, cifs_sb, full_path, data);
	case IO_REPARSE_TAG_LX_SYMLINK:
	case IO_REPARSE_TAG_AF_UNIX:
	case IO_REPARSE_TAG_LX_FIFO:
	case IO_REPARSE_TAG_LX_CHR:
	case IO_REPARSE_TAG_LX_BLK:
		if (le16_to_cpu(buf->ReparseDataLength) != 0) {
			cifs_dbg(VFS, "srv returned malformed buffer for reparse point: 0x%08x\n",
				 le32_to_cpu(buf->ReparseTag));
			return -EIO;
		}
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

int smb2_parse_reparse_point(struct cifs_sb_info *cifs_sb,
			     const char *full_path,
			     struct kvec *rsp_iov,
			     struct cifs_open_info_data *data)
{
	struct reparse_data_buffer *buf;
	struct smb2_ioctl_rsp *io = rsp_iov->iov_base;
	u32 plen = le32_to_cpu(io->OutputCount);

	buf = (struct reparse_data_buffer *)((u8 *)io +
					     le32_to_cpu(io->OutputOffset));
	return parse_reparse_point(buf, plen, cifs_sb, full_path, true, data);
}

bool cifs_reparse_point_to_fattr(struct cifs_sb_info *cifs_sb,
				 struct cifs_fattr *fattr,
				 struct cifs_open_info_data *data)
{
	struct reparse_posix_data *buf = data->reparse.posix;
	u32 tag = data->reparse.tag;

	if (tag == IO_REPARSE_TAG_NFS && buf) {
		if (le16_to_cpu(buf->ReparseDataLength) < sizeof(buf->InodeType))
			return false;
		switch (le64_to_cpu(buf->InodeType)) {
		case NFS_SPECFILE_CHR:
			if (le16_to_cpu(buf->ReparseDataLength) != sizeof(buf->InodeType) + 8)
				return false;
			fattr->cf_mode |= S_IFCHR;
			fattr->cf_rdev = reparse_nfs_mkdev(buf);
			break;
		case NFS_SPECFILE_BLK:
			if (le16_to_cpu(buf->ReparseDataLength) != sizeof(buf->InodeType) + 8)
				return false;
			fattr->cf_mode |= S_IFBLK;
			fattr->cf_rdev = reparse_nfs_mkdev(buf);
			break;
		case NFS_SPECFILE_FIFO:
			fattr->cf_mode |= S_IFIFO;
			break;
		case NFS_SPECFILE_SOCK:
			fattr->cf_mode |= S_IFSOCK;
			break;
		case NFS_SPECFILE_LNK:
			fattr->cf_mode |= S_IFLNK;
			break;
		default:
			WARN_ON_ONCE(1);
			return false;
		}
		goto out;
	}

	switch (tag) {
	case IO_REPARSE_TAG_INTERNAL:
		if (!(fattr->cf_cifsattrs & ATTR_DIRECTORY))
			return false;
		fallthrough;
	case IO_REPARSE_TAG_DFS:
	case IO_REPARSE_TAG_DFSR:
	case IO_REPARSE_TAG_MOUNT_POINT:
		/* See cifs_create_junction_fattr() */
		fattr->cf_mode = S_IFDIR | 0711;
		break;
	case IO_REPARSE_TAG_LX_SYMLINK:
		fattr->cf_mode |= S_IFLNK;
		fattr->cf_dtype = DT_LNK;
		break;
	case IO_REPARSE_TAG_LX_FIFO:
		fattr->cf_mode |= S_IFIFO;
		fattr->cf_dtype = DT_FIFO;
		break;
	case IO_REPARSE_TAG_AF_UNIX:
		fattr->cf_mode |= S_IFSOCK;
		fattr->cf_dtype = DT_SOCK;
		break;
	case IO_REPARSE_TAG_LX_CHR:
		fattr->cf_mode |= S_IFCHR;
		fattr->cf_dtype = DT_CHR;
		break;
	case IO_REPARSE_TAG_LX_BLK:
		fattr->cf_mode |= S_IFBLK;
		fattr->cf_dtype = DT_BLK;
		break;
	case 0: /* SMB1 symlink */
	case IO_REPARSE_TAG_SYMLINK:
	case IO_REPARSE_TAG_NFS:
		fattr->cf_mode &= ~S_IFMT;
		fattr->cf_mode |= S_IFLNK;
		break;
	default:
		return false;
	}
out:
	fattr->cf_dtype = S_DT(fattr->cf_mode);
	return true;
}
