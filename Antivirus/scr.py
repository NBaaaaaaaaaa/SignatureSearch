import sqlite3

def fetch_table_data(db_path, table_name):
    try:
        # Подключение к базе данных
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Выполнение SQL-запроса для получения данных из таблицы
        query = f"SELECT * FROM {table_name};"
        cursor.execute(query)
        rows = cursor.fetchall()

        # Получение имен колонок
        column_names = [description[0] for description in cursor.description]

        # Вывод заголовков таблицы
        print(f"{' | '.join(column_names)}")
        print("-" * (len(column_names) * 10))

        # Вывод данных таблицы
        for row in rows:
            print(" | ".join(map(str, row)))

    except sqlite3.Error as e:
        print(f"Ошибка при работе с SQLite: {e}")
    finally:
        if conn:
            conn.close()


# Укажите путь к вашей базе данных и имя таблицы
db_path = "antivir.db"
table_name = "QuarTable"
# FoundFiles
# Signatures
# QuarTable

fetch_table_data(db_path, table_name)
