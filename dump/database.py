import sqlite3
import threading
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class Database:
    _thread_local = threading.local()

    def __init__(self, db_path: str = "memory_analysis.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row  # 열 이름으로 접근 가능하게 설정
        self.set_wal_mode()
        self.create_tables()
        self.migrate_tables()

    def set_wal_mode(self):
        """SQLite의 Write-Ahead Logging 모드를 설정하여 동시성을 향상시킵니다."""
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            logger.info("SQLite WAL 모드가 활성화되었습니다.")
        except sqlite3.Error as e:
            logger.error(f"WAL 모드 설정 실패: {e}")

    def get_connection(self):
        """스레드 로컬 데이터베이스 연결을 반환합니다."""
        if not hasattr(self._thread_local, "connection"):
            try:
                self._thread_local.connection = sqlite3.connect(
                    self.db_path, check_same_thread=False, timeout=30
                )
                self._thread_local.connection.row_factory = (
                    sqlite3.Row
                )  # 열 이름으로 접근 가능하게 설정
                self._thread_local.connection.execute("PRAGMA journal_mode=WAL;")
                logger.debug("스레드 로컬 데이터베이스 연결이 설정되었습니다.")
            except sqlite3.Error as e:
                logger.error(f"스레드 로컬 연결 설정 실패: {e}")
                raise e
        return self._thread_local.connection

    def create_tables(self):
        """memory_entries 및 modules 테이블을 생성합니다."""
        try:
            with self.conn:
                # memory_entries 테이블 생성
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS memory_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        address TEXT,
                        offset TEXT,
                        raw TEXT,
                        string TEXT,
                        integer TEXT,
                        float_num REAL,
                        module TEXT
                    )
                    """
                )
                # modules 테이블 생성
                self.conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS modules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        base_address TEXT,
                        rss INTEGER
                    )
                    """
                )
            logger.info("데이터베이스 테이블이 성공적으로 생성 또는 확인되었습니다.")
        except sqlite3.Error as e:
            logger.error(f"테이블 생성 중 오류 발생: {e}")

    def migrate_tables(self):
        """필요한 데이터베이스 마이그레이션을 처리합니다."""
        # 필요 시 마이그레이션 로직을 구현
        pass

    def fetch_all_entries(self) -> List[Dict[str, any]]:
        """memory_entries 테이블에서 모든 메모리 항목을 가져옵니다."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, address, offset, raw, string, integer, float_num, module
                FROM memory_entries
                """
            )
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"데이터베이스로부터 {len(results)}개의 항목을 가져왔습니다.")
            return results
        except sqlite3.Error as e:
            logger.error(f"항목 가져오기 중 오류 발생: {e}")
            return []

    def fetch_all_modules(self) -> List[Dict[str, any]]:
        """modules 테이블에서 모든 모듈을 가져옵니다."""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, base_address, rss FROM modules
                """
            )
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"데이터베이스로부터 {len(results)}개의 모듈을 가져왔습니다.")
            return results
        except sqlite3.Error as e:
            logger.error(f"모듈 가져오기 중 오류 발생: {e}")
            return []

    def bulk_insert_entries(self, entries: List[Dict[str, any]]):
        """memory_entries 테이블에 메모리 항목을 일괄 삽입합니다."""
        required_keys = {
            "address",
            "offset",
            "raw",
            "string",
            "integer",
            "float_num",
            "module",
        }
        valid_entries = []
        invalid_entries = []

        for entry in entries:
            if not required_keys.issubset(entry.keys()):
                missing = required_keys - entry.keys()
                logger.error(f"필수 키가 누락된 항목 {missing}: {entry}")
                invalid_entries.append(entry)
            else:
                # 모든 필수 필드가 존재하도록 보장
                for key in required_keys:
                    if entry[key] is None:
                        if key == "float_num":
                            entry[key] = 0.0
                        else:
                            entry[key] = ""
                valid_entries.append(entry)

        if invalid_entries:
            logger.warning(
                f"필수 키 누락으로 인해 {len(invalid_entries)}개의 항목이 생략되었습니다."
            )

        if not valid_entries:
            logger.warning("데이터베이스에 삽입할 유효한 항목이 없습니다.")
            return

        try:
            conn = self.get_connection()
            with conn:
                conn.executemany(
                    """
                    INSERT INTO memory_entries (address, offset, raw, string, integer, float_num, module)
                    VALUES (:address, :offset, :raw, :string, :integer, :float_num, :module)
                    """,
                    valid_entries,
                )
                logger.debug(
                    f"데이터베이스에 {len(valid_entries)}개의 항목이 삽입되었습니다."
                )
        except sqlite3.Error as e:
            logger.error(f"항목 일괄 삽입 중 오류 발생: {e}")

    def bulk_insert_modules(self, modules: List[Dict[str, any]]):
        """modules 테이블에 모듈을 일괄 삽입합니다."""
        try:
            conn = self.get_connection()
            with conn:
                conn.executemany(
                    """
                    INSERT INTO modules (name, base_address, rss)
                    VALUES (:name, :base_address, :rss)
                    """,
                    modules,
                )
                logger.debug(
                    f"데이터베이스에 {len(modules)}개의 모듈이 삽입되었습니다."
                )
        except sqlite3.Error as e:
            logger.error(f"모듈 일괄 삽입 중 오류 발생: {e}")

    def bulk_update_entries(self, updates: List[Dict[str, any]]):
        """memory_entries 테이블의 메모리 항목을 일괄 업데이트합니다."""
        try:
            conn = self.get_connection()
            with conn:
                for update in updates:
                    conn.execute(
                        """
                        UPDATE memory_entries
                        SET offset = :offset,
                            string = :string,
                            integer = :integer,
                            float_num = :float_num
                        WHERE id = :id
                        """,
                        update,
                    )
                logger.debug(
                    f"데이터베이스에 {len(updates)}개의 항목이 업데이트되었습니다."
                )
        except sqlite3.Error as e:
            logger.error(f"항목 일괄 업데이트 중 오류 발생: {e}")

    def search_entries(self, field: str, query: str) -> List[Dict]:
        """
        특정 필드와 쿼리를 기반으로 메모리 항목을 검색합니다.

        :param field: 검색할 필드 (예: 'address', 'module').
        :param query: 검색 쿼리 문자열.
        :return: 검색 결과를 담은 딕셔너리 목록.
        """
        allowed_fields = {
            "address",
            "offset",
            "raw",
            "string",
            "integer",
            "float_num",
            "module",
        }
        if field not in allowed_fields:
            logger.error(f"유효하지 않은 검색 필드: {field}")
            raise ValueError(f"필드 '{field}'은(는) 유효한 검색 필드가 아닙니다.")

        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            sql_query = f"SELECT * FROM memory_entries WHERE {field} LIKE ?"
            cursor.execute(sql_query, (f"%{query}%",))
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]
            logger.info(
                f"검색 완료. 필드 '{field}'에서 '{query}'와(과) 일치하는 {len(results)}개의 항목을 찾았습니다."
            )
            return results
        except sqlite3.Error as e:
            logger.error(f"항목 검색 중 오류 발생: {e}")
            return []

    def close(self):
        """모든 데이터베이스 연결을 닫습니다."""
        try:
            # 스레드 로컬 연결이 존재하면 닫기
            conn = getattr(self._thread_local, "connection", None)
            if conn:
                conn.close()
                del self._thread_local.connection
                logger.debug("스레드 로컬 데이터베이스 연결이 닫혔습니다.")

            # 메인 연결 닫기
            if self.conn:
                self.conn.close()
                logger.debug("메인 데이터베이스 연결이 닫혔습니다.")
        except sqlite3.Error as e:
            logger.error(f"데이터베이스 연결 종료 중 오류 발생: {e}")
