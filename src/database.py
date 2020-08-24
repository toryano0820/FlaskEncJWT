import pyodbc
import re
import time
from enum import Enum


class DBEngine(Enum):
    MSSQL=0
    MYSQL=1


class DBConn:
    @property
    def name(self):
        return self.__name

    def __init__(self, name, connection_string, _pool_index=-1):
        self.__name = name
        self.__is_busy = False
        self.__pool_index = _pool_index
        self.__connection_string = connection_string
        self.__engine = DBEngine.MYSQL if "mysql" in connection_string.lower() else DBEngine.MSSQL
        self.__conn = pyodbc.connect(connection_string)

    def is_busy(self):
        return self.__is_busy

    def __set_busy(self, busy):
        self.__is_busy = busy

    def is_connected(self):
        try:
            self.__conn.cursor().execute("SELECT @@VERSION")
            return True
        except:
            self.__conn = pyodbc.connect(self.__connection_string)
            return False

    def execute(self, target, *args, error_callback=None, max_try=3):
        self.__set_busy(True)
        error = None

        for i in range(max_try):
            try:
                cursor = DBConn.Cursor(self.__conn.cursor(), self.__engine)
                data = target(cursor, *args)

                # if self.__pool_index != -1:
                #     print("PYODBC: %s: %d" % (self.name, self.__pool_index))

                cursor.close()

                self.__set_busy(False)

                return data
            except Exception as ex:
                self.__conn = pyodbc.connect(self.__connection_string)

                if self.__pool_index == -1:
                    print("[ERROR] PYODBC({}.execute): {}: {}".format(
                        self.name, i, ex))
                else:
                    print("[ERROR] PYODBC({}[{}].execute): {}: {}".format(
                        self.name, self.__pool_index, i, ex))

                if callable(error_callback):
                    error_callback(ex)

                error = ex

        self.__set_busy(False)
        raise Exception("Error while processing '{}' procedure: {}".format(self.name, error))

    def cursor(self):
        return DBConn.Cursor(self.__conn.cursor(), self.__engine, self.__set_busy)


    class Cursor:
        def __init__(self, cursor, db_engine: DBEngine, busy_setter=None):
            # cursor.fast_executemany = True
            self.__base = cursor
            self.execute = cursor.execute
            self.commit = cursor.commit
            self.rollback = cursor.rollback
            self.fetchone = cursor.fetchone
            self.fetchall = cursor.fetchall
            self.close = cursor.close
            self.executemany = cursor.executemany
            if db_engine == DBEngine.MSSQL:
                self.callproc = self.__callproc_mssql
                self.callprocmany = self.__callprocmany_mssql
            else:
                self.callproc = self.__callproc_mysql
                self.callprocmany = self.__callprocmany_mysql
            self.__busy_setter = busy_setter

        def __enter__(self):
            if callable(self.__busy_setter):
                self.__busy_setter(True)
            return self

        def __exit__(self, *args):
            self.close()
            if callable(self.__busy_setter):
                self.__busy_setter(False)

        def __callproc_mssql(self, stored_proc, *args):
            if "?" in stored_proc:
                return self.execute("EXECUTE {sp};".format(sp=stored_proc), *args)
            else:
                return self.execute("EXECUTE {sp} {markers};".format(sp=stored_proc, markers=", ".join(("?",) * len(args))), *args)

        def __callprocmany_mssql(self, stored_proc, args_list=tuple()):
            if "?" in stored_proc:
                return self.executemany("EXECUTE {sp};".format(sp=stored_proc), args_list)
            else:
                return self.executemany("EXECUTE {sp} {markers};".format(sp=stored_proc, markers=", ".join(("?",) * len(args_list[0]))), args_list)

        def __callproc_mysql(self, stored_proc, *args):
            if "?" in stored_proc:
                return self.execute("CALL {sp};".format(sp=stored_proc), *args)
            else:
                return self.execute("CALL {sp}({markers});".format(sp=stored_proc, markers=", ".join(("?",) * len(args))), *args)

        def __callprocmany_mysql(self, stored_proc, args_list=tuple()):
            if "?" in stored_proc:
                return self.executemany("CALL {sp};".format(sp=stored_proc), args_list)
            else:
                return self.executemany("CALL {sp}({markers});".format(sp=stored_proc, markers=", ".join(("?",) * len(args_list[0]))), args_list)

        def __iter__(self):
            return self.__base


class DBPool:
    POOL = dict()

    @staticmethod
    def add(name, connection_string, pool_size=10):
        if name not in DBPool.POOL:
            DBPool.POOL[name] = list()

        for i in range(pool_size):
            DBPool.POOL[name].append(
                DBConn(name, connection_string, _pool_index=i))

    @staticmethod
    def execute(name, target, *args, error_callback=None):
        if name not in DBPool.POOL:
            raise Exception(
                "DBPool: Connection to '{}' not initialized.".format(name))

        while True:
            for conn in DBPool.POOL[name]:
                if not conn.is_busy() and conn.is_connected():
                    return conn.execute(target, *args, error_callback=error_callback)

    @staticmethod
    def cursor(name):
        if name not in DBPool.POOL:
            raise Exception(
                "DBPool: Connection to '{}' not initialized.".format(name))

        while True:
            for conn in DBPool.POOL[name]:
                if not conn.is_busy() and conn.is_connected():
                    return conn.cursor()
