targets = [
    # keep sorted
    "art",
    "autogvm",
    "canoe",
    "chora",
    "gen3auto",
    "hamoa",
    "lahaina",
    "bengal",
    "malabar",
    "pineapple",
    "parrot",
    "seraph",
    "sun",
    "vienna",
]

la_variants = [
    # keep sorted
    "consolidate",
    "gki",
    "perf",
]

lv_variants = [
    "debug-defconfig",
    "defconfig",
]

le_targets = [
    # keep sorted
    "alor-le",
    "sun-allyes",
]

le_32_targets = [
    # keep sorted
    "sa510m",
    "sa510m.1g",
]

le_variants = [
    # keep sorted
    "debug-defconfig",
    "perf-defconfig",
    "defconfig",
]

le_32_variants = [
    # keep sorted
    "debug-defconfig",
    "perf-defconfig",
]

vm_types = [
    "tuivm",
    "oemvm",
]

vm_target_bases = [
    "sun",
    "canoe",
    "hamoa",
]

vm_targets = ["{}-{}".format(t, vt) for t in vm_target_bases for vt in vm_types]

vm_variants = [
    # keep sorted
    "debug-defconfig",
    "defconfig",
]

def get_all_la_variants():
    return [(t, v) for t in targets for v in la_variants]

def get_all_lv_variants():
    return [(t, v) for t in targets for v in lv_variants]

def get_all_le_variants():
    return [(t, v) for t in le_targets for v in le_variants]

def get_all_vm_variants():
    return [(t, v) for t in vm_targets for v in vm_variants]

def get_all_non_la_variants():
    return get_all_le_variants() + get_all_vm_variants()

def get_all_le_32_variants():
    return [(t, v) for t in le_32_targets for v in le_32_variants]

def get_all_variants():
    return get_all_la_variants() + get_all_lv_variants() + get_all_le_variants() + get_all_vm_variants() + get_all_le_32_variants()
