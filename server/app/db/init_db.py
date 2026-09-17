from app.db.session import engine, init_database


def main() -> None:
    init_database(engine)


if __name__ == "__main__":
    main()
