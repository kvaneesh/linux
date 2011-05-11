#include <linux/fs.h>
#include "ext4.h"
#include "acl.h"
#include "richacl.h"

int
ext4_check_acl(struct inode *inode, int mask, unsigned int flags)
{
#ifdef CONFIG_EXT4_FS_POSIX_ACL
	if (IS_POSIXACL(inode))
		return ext4_check_posix_acl(inode, mask, flags);
	else
#endif
#ifdef CONFIG_EXT4_FS_RICHACL
	if (IS_RICHACL(inode))
		return ext4_check_richacl(inode, mask, flags);
	else
#endif
		return -EAGAIN;
}
