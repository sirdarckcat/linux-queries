select
    vuln_id,
    introduced_before_4_14 and fixed_after_4_14 and not fixed_on_4_14 needs_fix_4_14,
    introduced_before_4_19 and fixed_after_4_19 and not fixed_on_4_19 needs_fix_4_19,
    introduced_before_5_4 and fixed_after_5_4 and not fixed_on_5_4 needs_fix_5_4,
    introduced_before_5_10 and fixed_after_5_10 and not fixed_on_5_10 needs_fix_5_10,
    introduced_before_5_15 and fixed_after_5_15 and not fixed_on_5_15 needs_fix_5_15,
    introduced_before_6_1 and fixed_after_6_1 and not fixed_on_6_1 needs_fix_6_1,
    introduced_before_6_6 and fixed_after_6_6 and not fixed_on_6_6 needs_fix_6_6
from (
    select
        vuln_id,
        sum((fixes_tags_major=4 and fixes_tags_minor<=14) or (fixes_tags_major<4)) introduced_before_4_14,
        sum((fixes_tags_major=4 and fixes_tags_minor<=19) or (fixes_tags_major<4)) introduced_before_4_19,
        sum((fixes_tags_major=5 and fixes_tags_minor<=4) or (fixes_tags_major<5)) introduced_before_5_4,
        sum((fixes_tags_major=5 and fixes_tags_minor<=10) or (fixes_tags_major<5)) introduced_before_5_10,
        sum((fixes_tags_major=5 and fixes_tags_minor<=15) or (fixes_tags_major<5)) introduced_before_5_15,
        sum((fixes_tags_major=6 and fixes_tags_minor<=1) or (fixes_tags_major<6)) introduced_before_6_1,
        sum((fixes_tags_major=6 and fixes_tags_minor<=6) or (fixes_tags_major<6)) introduced_before_6_6,

        sum((fixed_tags_major=4 and fixed_tags_minor>14) or ((fixed_tags_major=4 and fixed_tags_minor=14 and fixed_tags_patch>0)) or (fixed_tags_major>4)) fixed_after_4_14,
        sum((fixed_tags_major=4 and fixed_tags_minor>19) or ((fixed_tags_major=4 and fixed_tags_minor=19 and fixed_tags_patch>0)) or (fixed_tags_major>4)) fixed_after_4_19,
        sum((fixed_tags_major=5 and fixed_tags_minor>4) or ((fixed_tags_major=5 and fixed_tags_minor=4 and fixed_tags_patch>0)) or (fixed_tags_major>5)) fixed_after_5_4,
        sum((fixed_tags_major=5 and fixed_tags_minor>10) or ((fixed_tags_major=5 and fixed_tags_minor=10 and fixed_tags_patch>0)) or (fixed_tags_major>5)) fixed_after_5_10,
        sum((fixed_tags_major=5 and fixed_tags_minor>15) or ((fixed_tags_major=5 and fixed_tags_minor=15 and fixed_tags_patch>0)) or (fixed_tags_major>5)) fixed_after_5_15,
        sum((fixed_tags_major=6 and fixed_tags_minor>1) or ((fixed_tags_major=6 and fixed_tags_minor=1 and fixed_tags_patch>0)) or (fixed_tags_major>6)) fixed_after_6_1,
        sum((fixed_tags_major=6 and fixed_tags_minor>6) or ((fixed_tags_major=6 and fixed_tags_minor=6 and fixed_tags_patch>0)) or (fixed_tags_major>6)) fixed_after_6_6,

        sum(fixed_tags_major=4 and fixed_tags_minor=14) fixed_on_4_14,
        sum(fixed_tags_major=4 and fixed_tags_minor=19) fixed_on_4_19,
        sum(fixed_tags_major=5 and fixed_tags_minor=4) fixed_on_5_4,
        sum(fixed_tags_major=5 and fixed_tags_minor=10) fixed_on_5_10,
        sum(fixed_tags_major=5 and fixed_tags_minor=15) fixed_on_5_15,
        sum(fixed_tags_major=6 and fixed_tags_minor=1) fixed_on_6_1,
        sum(fixed_tags_major=6 and fixed_tags_minor=6) fixed_on_6_6,
        vuln_id
    from (
        select
            vuln_id,
            fixed_commit,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixes_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=1 LIMIT 1) AS INTEGER) fixes_tags_major,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixes_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=2 LIMIT 1) AS INTEGER) fixes_tags_minor,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixes_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=3 LIMIT 1) AS INTEGER) fixes_tags_patch,
            fixes_commit,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixed_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=1 LIMIT 1) AS INTEGER) fixed_tags_major,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixed_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=2 LIMIT 1) AS INTEGER) fixed_tags_minor,
            CAST((WITH RECURSIVE semver(v, depth, full) AS (SELECT "", 0, fixed_tags||"." UNION ALL SELECT substring(full, 0, instr(full, ".")), depth + 1, substring(full, instr(full, ".") + 1) FROM semver WHERE full != "") SELECT v FROM semver WHERE depth=3 LIMIT 1) AS INTEGER) fixed_tags_patch
        from (
            select
                vuln_id,
                fixed_commit,
                fixes_commit,
                REPLACE(SUBSTRING(REPLACE(REPLACE(REPLACE(fixes_tags.tags, "-", "~"), "linux-", "v"), ".y", ""), LENGTH("tags/v") + 1)||"~", "~", ".0.~") `fixes_tags`,
                REPLACE(SUBSTRING(REPLACE(REPLACE(REPLACE(fixed_tags.tags, "-", "~"), "linux-", "v"), ".y", ""), LENGTH("tags/v") + 1)||"~", "~", ".0.~") `fixed_tags`
            from
                (
                    select
                        vuln_id,
                        fixed_commit,
                        (
                            select
                                `commit`
                            from
                                tags
                            where
                                `commit` >= fixes_short and
                                `commit` < fixes_short||'g'
                        ) fixes_commit
                    from
                        (
                            select
                                SUBSTR(fixes_commit, 0, INSTR(fixes_commit, " ")) fixes_short,
                                fixed_commit,
                                vuln_id
                            from (
                                select
                                    cve vuln_id,
                                    `commit` fixed_commit,
                                    (
                                        select
                                            fixes
                                        from
                                            fixes
                                        where
                                            `commit`=cve.`commit`
                                    ) fixes_commit
                                from
                                    cve
                                union all
                                select
                                    cve vuln_id,
                                    upstream.`commit` fixed_commit,
                                    (
                                        select
                                            fixes
                                        from
                                            fixes
                                        where
                                            `commit`=cve.`commit`
                                    ) fixes_commit
                                from
                                    upstream
                                join
                                    cve
                                on
                                    cve.`commit`=upstream.upstream
                                union all
                                select
                                    syzkaller vuln_id,
                                    `commit` fixed_commit,
                                    (
                                        select
                                            fixes
                                        from
                                            fixes
                                        where
                                            `commit`=syzkaller.`commit`
                                    ) fixes_commit
                                from
                                    syzkaller
                                union all
                                select
                                    syzkaller vuln_id,
                                    upstream.`commit` fixed_commit,
                                    (
                                        select
                                            fixes
                                        from
                                            fixes
                                        where
                                            `commit`=syzkaller.`commit`
                                    ) fixes_commit
                                from
                                    upstream
                                join
                                    syzkaller
                                on
                                    syzkaller.`commit`=upstream.upstream
                            )
                        )
                    where
                        length(fixes_short)>0
                )
            join
                tags fixes_tags
            on
                fixes_tags.`commit`=fixes_commit
            join
                tags fixed_tags
            on
                fixed_tags.`commit`=fixed_commit
        )
    )
    group by vuln_id
);
