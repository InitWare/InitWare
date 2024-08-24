/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "path-lookup.h"
#include "path-util.h"
#include "unit-file.h"

bool unit_type_may_alias(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_DEVICE,
                      UNIT_TIMER,
                      UNIT_PATH);
}

bool unit_type_may_template(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_TIMER,
                      UNIT_PATH);
}

int unit_symlink_name_compatible(const char *symlink, const char *target, bool instance_propagation) {
        _cleanup_free_ char *template = NULL;
        int r, un_type1, un_type2;

        un_type1 = unit_name_classify(symlink);

        /* The straightforward case: the symlink name matches the target and we have a valid unit */
        if (streq(symlink, target) &&
            (un_type1 & (UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE)))
                return 1;

        r = unit_name_template(symlink, &template);
        if (r == -EINVAL)
                return 0; /* Not a template */
        if (r < 0)
                return r;

        un_type2 = unit_name_classify(target);

        /* An instance name points to a target that is just the template name */
        if (un_type1 == UNIT_NAME_INSTANCE &&
            un_type2 == UNIT_NAME_TEMPLATE &&
            streq(template, target))
                return 1;

        /* foo@.target.requires/bar@.service: instance will be propagated */
        if (instance_propagation &&
            un_type1 == UNIT_NAME_TEMPLATE &&
            un_type2 == UNIT_NAME_TEMPLATE &&
            streq(template, target))
                return 1;

        return 0;
}

int unit_validate_alias_symlink_or_warn(int log_level, const char *filename, const char *target) {
        _cleanup_free_ char *src = NULL, *dst = NULL;
        _cleanup_free_ char *src_instance = NULL, *dst_instance = NULL;
        UnitType src_unit_type, dst_unit_type;
        UnitNameFlags src_name_type, dst_name_type;
        int r;

        /* Check if the *alias* symlink is valid. This applies to symlinks like
         * /etc/systemd/system/dbus.service → dbus-broker.service, but not to .wants or .requires symlinks
         * and such. Neither does this apply to symlinks which *link* units, i.e. symlinks to outside of the
         * unit lookup path.
         *
         * -EINVAL is returned if the something is wrong with the source filename or the source unit type is
         *         not allowed to symlink,
         * -EXDEV if the target filename is not a valid unit name or doesn't match the source,
         * -ELOOP for an alias to self.
         */

        r = path_extract_filename(filename, &src);
        if (r < 0)
                return r;

        r = path_extract_filename(target, &dst);
        if (r < 0)
                return r;

        /* src checks */

        src_name_type = unit_name_to_instance(src, &src_instance);
        if (src_name_type < 0)
                return log_full_errno(log_level, src_name_type,
                                      "%s: not a valid unit name \"%s\": %m", filename, src);

        src_unit_type = unit_name_to_type(src);
        assert(src_unit_type >= 0); /* unit_name_to_instance() checked the suffix already */

        if (!unit_type_may_alias(src_unit_type))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EINVAL),
                                      "%s: symlinks are not allowed for units of this type, rejecting.",
                                      filename);

        if (src_name_type != UNIT_NAME_PLAIN &&
            !unit_type_may_template(src_unit_type))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EINVAL),
                                      "%s: templates not allowed for %s units, rejecting.",
                                      filename, unit_type_to_string(src_unit_type));

        /* dst checks */

        if (streq(src, dst))
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "%s: unit self-alias: %s → %s, ignoring.",
                                       filename, src, dst);

        dst_name_type = unit_name_to_instance(dst, &dst_instance);
        if (dst_name_type < 0)
                return log_full_errno(log_level, dst_name_type == -EINVAL ? SYNTHETIC_ERRNO(EXDEV) : dst_name_type,
                                      "%s points to \"%s\" which is not a valid unit name: %m",
                                      filename, dst);

        if (!(dst_name_type == src_name_type ||
              (src_name_type == UNIT_NAME_INSTANCE && dst_name_type == UNIT_NAME_TEMPLATE)))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
                                      "%s: symlink target name type \"%s\" does not match source, rejecting.",
                                      filename, dst);

        if (dst_name_type == UNIT_NAME_INSTANCE) {
                assert(src_instance);
                assert(dst_instance);
                if (!streq(src_instance, dst_instance))
                        return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
                                              "%s: unit symlink target \"%s\" instance name doesn't match, rejecting.",
                                              filename, dst);
        }

        dst_unit_type = unit_name_to_type(dst);
        if (dst_unit_type != src_unit_type)
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EXDEV),
                                      "%s: symlink target \"%s\" has incompatible suffix, rejecting.",
                                      filename, dst);

        return 0;
}
