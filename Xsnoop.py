import enum
import argparse
import subprocess
from collections import namedtuple


def bpftrace(args: str) -> [str]:
    with subprocess.Popen(
        f"bpftrace {args}",
        shell=True,
        stdout=subprocess.PIPE,
        universal_newlines=True,
    ) as process:
        for line in process.stdout:
            yield line


KfuncArg = namedtuple("KfuncArg", "name type type_cls")


class KfuncArgCls(enum.Enum):
    Pointer = 1
    String = 2
    Integer = 3
    Other = 4


class Line:
    def __init__(self, line: str):
        self.line = line

    def is_kfunc(self) -> bool:
        return self.line.startswith("kfunc:")

    def to_kfunc(self) -> str:
        return self.line.strip()

    def is_arg(self) -> bool:
        return self.line.startswith(" ") and self.line.strip().count(" ") > 0

    def to_arg(self) -> KfuncArg:
        type, name = self.line.strip().rsplit(" ", 1)
        if type.startswith("char"):
            type_cls = KfuncArgCls.String
        elif type.endswith("*"):
            type_cls = KfuncArgCls.Pointer
        elif "int" in type:
            type_cls = KfuncArgCls.Integer
        else:
            type_cls = KfuncArgCls.Other
        return KfuncArg(name, type, type_cls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Snoop everything")
    parser.add_argument(
        "--X-type",
        required=True,
        help='e.g. "struct net_device *"',
    )
    parser.add_argument(
        "--no-type",
        required=False,
        help='e.g. "struct sk_buff *"',
    )
    parser.add_argument(
        "--X-filter",
        required=False,
        help='e.g. "X->name == "eth0"',
        default="true",
    )
    parser.add_argument(
        "--X-output",
        required=True,
        help='e.g. "X->name:%%s,X->ifindex:%%d"',
    )
    flags = parser.parse_args()

    # kfunc:vmlinux:xfrm_dev_state_flush => ([(net, pointer)], dev)}
    targets = {}

    skip_as_no_type = skip_as_no_kfunc = False
    for line in bpftrace("-lv"):
        line = Line(line)

        if line.is_kfunc():
            skip_as_no_type = skip_as_no_kfunc = False
            kfunc = line.to_kfunc()
            args = []
            continue

        if not skip_as_no_kfunc and not skip_as_no_type and line.is_arg():
            arg = line.to_arg()
            args.append((arg.name, arg.type_cls))

            if arg.type == flags.X_type:
                X_arg_name = arg.name
                targets[kfunc] = (args, X_arg_name)

            if arg.type == flags.no_type:
                if kfunc in targets:
                    del targets[kfunc]
                skip_as_no_type = True

            continue

        skip_as_no_kfunc = True

    i = 0
    for kfunc, (args, X_arg_name) in targets.items():
        if X_arg_name == "retval":
            continue

        i += 1
        print(
            """
{kfunc}
{{
    $X = args->{X_arg_name};
    if ({cond}) {{
        printf("{kfunc}() \\n");
    }}
}}""".format(
                cond=flags.X_filter.replace("X", '$X'),
                kfunc=kfunc,
                X_arg_name=X_arg_name,
            )
        )
