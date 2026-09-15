def load_scope(scope_file):
    targets = []

    with open(scope_file, "r", encoding="utf-8") as file:
        for line in file:
            target = line.strip()

            if target and not target.startswith("#"):
                targets.append(target)

    return targets