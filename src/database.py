import pyodbc


class Connection:
    def __init__(self, connection_string):
        self.__connection = None
        self.__connection_string = connection_string
        self.__current_cursor = None
        self.connect()

    def connect(self):
        if self.__connection:
            self.__connection.close()
        self.__connection = pyodbc.connect(self.__connection_string, autocommit=True)

    @property
    def _pyodbc_cursor(self):
        try:
            return self.__connection.cursor()
        except pyodbc.ProgrammingError:
            self.connect()
            return self.__connection.cursor()


    @property
    def busy(self):
        return bool(self.__current_cursor)

    def __enter__(self):
        self.__current_cursor = Cursor(self)
        return self.__current_cursor

    def __exit__(self, *args, **kwargs):
        self.__current_cursor = None


class Cursor:
    def __init__(self, connection):
        self.__connection = connection

    @property
    def _pyodbc_cursor(self):
        self.__cursor = self.__connection._pyodbc_cursor
        self.fetchone = self.__cursor.fetchone
        self.fetchmany = self.__cursor.fetchmany
        return self.__cursor

    def __iter__(self):
        return self.__cursor

    def execute(self, sql, *args):
        retry = 3
        for i in range(retry):
            try:
                self._pyodbc_cursor.execute(sql, args)
                return self
            except pyodbc.OperationalError:
                if i == retry - 2:
                    return False

        return False

    def callproc(self, sp_name, *args):
        self.execute(f'CALL {sp_name}({",".join(["?"] * len(args))});', *args)


class Pool:
    def __init__(self, connection_string, max_size=8):
        self.__connection_string = connection_string
        self.__pool = []
        self.max_size = max_size

    def cursor(self):
        while True:
            for conn in self.__pool:
                if not conn.busy:
                    return conn

            if len(self.__pool) < self.max_size:
                self.__pool.append(Connection(self.__connection_string))
