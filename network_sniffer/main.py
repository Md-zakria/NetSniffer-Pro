"""Application entrypoint for the CustomTkinter network sniffer."""

from ui.app import NetworkSnifferApp


def main() -> None:
    app = NetworkSnifferApp()
    app.run()


if __name__ == "__main__":
    main()
