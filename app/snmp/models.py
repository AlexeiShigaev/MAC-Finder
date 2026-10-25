from typing import List, Optional

from pydantic import BaseModel, computed_field


class QueryOID(BaseModel):
    host: str
    port: int = 161
    community: str = "public"
    snmp_ver: int = 1  # 0 - for SNMP v1, 1 - for SNMP v2c (default)
    oid_start: str
    oid_stop: str
    timeout: int = 2
    retries: int = 2

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "1. short query": {
                        "host": "IP addr, кого опрашиваем",
                        "oid_start": "oid.1",
                        "oid_stop": "oid.2",
                    },
                    "2. full query": {
                        "host": "IP addr, кого опрашиваем",
                        "port": 161,
                        "community": "public",
                        "snmp_ver": 1,
                        "oid_start": "oid.1",
                        "oid_stop": "oid.2",
                        "timeout": "timeout",
                        "retries": "timeout",
                    }
                }
            ]
        }
    }


class RawDataQueryOID(BaseModel):
    """Сырой результат SNMP-walk: OID-границы + список [oid, value]."""
    oid_start: str = ""
    oid_stop: str = ""
    result_list: List = []
    error: Optional[str] = None

    @computed_field
    @property
    def count(self) -> int:
        return len(self.result_list)


class ResultQueryOID(BaseModel):
    """Обработанный результат: список структурированных записей."""
    results_list: List = []
    error: Optional[str] = None

    @computed_field
    @property
    def count(self) -> int:
        return len(self.results_list)
    
