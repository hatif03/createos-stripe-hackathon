# SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
"""Loads a TOML config and prints a greeting. No import-time side effects:
all behaviour happens inside run(), which must be called explicitly."""
import tomllib


def run(config_path):
    try:
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        raise SystemExit(f"needsconfig: config file not found: {config_path}")
    except tomllib.TOMLDecodeError as e:
        raise SystemExit(f"needsconfig: invalid TOML in {config_path}: {e}")

    try:
        name = config["name"]
        repeat = config["repeat"]
    except KeyError as e:
        raise SystemExit(f"needsconfig: missing required key {e} in {config_path}")

    for _ in range(repeat):
        print(f"Hello, {name}!")


if __name__ == "__main__":
    import sys

    run(sys.argv[1])
