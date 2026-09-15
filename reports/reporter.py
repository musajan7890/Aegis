from datetime import datetime


def generate_report(
    target: str,
    findings: list[dict],
    output_file: str
) -> None:

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write("=" * 70 + "\n")
        file.write("                 AEGIS SECURITY ASSESSMENT\n")
        file.write("=" * 70 + "\n")
        file.write("\n")

        file.write(f"Target: {target}\n")
        file.write(
            f"Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        file.write("\n")
        file.write("-" * 70 + "\n")
        file.write("                         SUMMARY\n")
        file.write("-" * 70 + "\n")
        file.write("\n")

        file.write(
            f"Total Findings: {len(findings)}\n"
        )

        file.write("\n")

        if not findings:

            file.write(
                "No findings were generated.\n"
            )

        else:

            for number, finding in enumerate(
                findings,
                start=1
            ):

                file.write(
                    f"{number}. "
                    f"[{finding['severity']}] "
                    f"{finding['title']}\n"
                )

        file.write("\n")
        file.write("=" * 70 + "\n")
        file.write("                        FINDINGS\n")
        file.write("=" * 70 + "\n")
        file.write("\n")

        for number, finding in enumerate(
            findings,
            start=1
        ):

            file.write(
                f"Finding #{number}\n"
            )

            file.write(
                f"Title: {finding['title']}\n"
            )

            file.write(
                f"Severity: {finding['severity']}\n"
            )

            file.write("\n")

            file.write(
                "Description:\n"
            )

            file.write(
                f"{finding['description']}\n"
            )

            file.write("\n")

            file.write(
                "Evidence:\n"
            )

            file.write(
                f"{finding['evidence']}\n"
            )

            file.write("\n")

            file.write(
                "Impact:\n"
            )

            file.write(
                f"{finding['impact']}\n"
            )

            file.write("\n")

            file.write(
                "Recommendation:\n"
            )

            file.write(
                f"{finding['recommendation']}\n"
            )

            file.write("\n")
            file.write("-" * 70 + "\n")
            file.write("\n")