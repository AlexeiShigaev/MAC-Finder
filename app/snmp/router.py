from datetime import timedelta

import pysnmp
from fastapi import APIRouter, Depends
from pysnmp.proto.rfc1902 import TimeTicks

from app.auth.auth import get_current_user
from app.auth.models import UserData4Auth
from app.snmp.oid_query import (
    QueryOID, get_oid_from_to, extract_mac_vlan_port, ResultQueryOID,
    extract_port_and_port_name, extract_info_ip, extract_arp_table, extract_mac_addr
)


router = APIRouter(prefix="/snmp", tags=["SNMP api"])


@router.post("/", summary="Абстрактный запрос. Универсальный.")
async def query_oid_range(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос нескольких oid из промежутка начиная от **oid_start** включительно и до **oid_stop**, исключая последний.

    Версию SNMP можно указать через snmp_ver: **0 - for SNMP v1, 1 - for SNMP v2c (default)**

    Эквивалент `c:\SnmpWalk -v:2c -c:public -r:host -os:1.3.6.1.2.1.1.1 -op:1.3.6.1.2.1.1.7`

    **Необходимо передать минимум три параметра:**
    - **host**: IP-addr - хост опроса.
    - **oid_start**: с какого oid начинаем, например 1.3.6.1.2.1.1.1
    - **oid_stop**: до какого oid, например 1.3.6.1.2.1.1.7

    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.

    Возвращает словарь вида
    ```
    {
        "results_list": [
        {
            "oid": "1.3.6.1.2.1.1.6.0",
            "value": "value"
        },
        ],
        "count": int,
        "error": str,
    }
    ```
    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.
    """
    results = ResultQueryOID()

    # Делаеам SNMP запрос к хосту
    ret_data = await get_oid_from_to(query)

    results.results_list = [{"oid": str(elem[0]), "value": str(elem[1])} for elem in ret_data["result_list"]]
    results.count, results.error = (ret_data["count"], ret_data["error"])

    return results


@router.post("/query/info", summary="Запрос основной информации о приборе.")
async def query_info(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос наименования прибора, его время аптайм. Так же комментарии, расположение (если заполнено).

    аналог `SnmpWalk -csv -v:2c -r:host -os:.1.3.6.1.2.1.1.1 -op:.1.3.6.1.2.1.1.7`

    Возвращает словарь вида
    ```
    {
        "results_list": [
            "HPE OfficeConnect Switch 1920S 48G 4SFP JL382A.....",
            "59 days, 21:28:43",
            "where is",
            "comment"
        ],
        "count": int,
        "error": str,
    }
    ```
    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.
    """

    # Запрашиваем сырые данные от хоста
    ret_data = await get_oid_from_to(query)
    if ret_data["error"] is not None:
        return ret_data

    # распаковываем данные
    results = ResultQueryOID()

    try:
        # убираю пустые строки, перевожу аптайм в строку, на выходе словарь

        for el in ret_data["result_list"]:
            if isinstance(el[1], TimeTicks):
                results.results_list.append(
                    {str(el[0]): str(timedelta(milliseconds=10 * int(el[1])))}
                )
            else:
                if not str(el[1]).startswith("1.3.6.1"):
                    results.results_list.append(
                        {str(el[0]): str(el[1])}
                    )

        results.count = len(results.results_list)
    except Exception as ex:
        print("error: {}".format(ex))
        results.error = "Error was occurred: {}".format(ex)
    return results


@router.post("/query/info_ip", summary="Запрос локальных IP адресов устройства")
async def query_info_ip(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос локальных IP адресов устройства.

    Аналог запросов:
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:.1.3.6.1.2.1.4.20.1 -op:.1.3.6.1.2.1.4.20.2`

    На выходе словарь вида:
    ```
    {
        "results_list": [
            {
                "10.0.0.1": {
                    "ipAdEntAddr": "10.0.0.1",
                    "ipAdEntIfIndex": "53",
                    "ipAdEntNetMask": "255.255.252.0",
                    "ipAdEntBcastAddr": "1",
                    "ipAdEntReasmMaxSize": "65535"
                }
            }
        ],
        "count": 1,
        "error": null
    }
    ```
    """
    # Запрашиваем сырые данные от хоста
    ret_data = await get_oid_from_to(query)
    if ret_data["error"] is not None:
        return ret_data
    # разворачиваем данные в словарь
    return extract_info_ip(ret_data)


@router.post("/query/macs", summary="Запрос: на каких портах коммутатора какие маки светятся, в каких VLan-ах")
async def query_mac_vlan_port(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос: на каких портах коммутатора какие маки светятся, в каких VLan-ах.

    Аналог запросов:
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:1.3.6.1.2.1.17.7.1.2.2.1.2 -op:1.3.6.1.2.1.17.7.1.2.2.1.3`

    Возвращает словарь вида
    ```
    {
        "results_list": [
            {
                "mac": str,
                "vlan": str,
                "logical_interface_id": str
            }
        ],
        "count": int,
        "error": str,
    }
    ```
    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.
    """
    # Запрашиваем сырые данные от хоста
    ret_data = await get_oid_from_to(query)
    if ret_data["error"] is not None:
        return ret_data

    # Вынимаем маки, вланы, порты
    return extract_mac_vlan_port(ret_data)


@router.post("/query/ports", summary="Запрос портов/интерфейсов коммутатора")
async def query_ports(query: QueryOID, user: UserData4Auth = Depends(get_current_user)):
    """
    Запрос портов/интерфейсов коммутатора, в его внутренних нумерации и именовании портов/интерфейсов.

    Аналог запросов:
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:1.3.6.1.2.1.31.1.1.1.1 -op:1.3.6.1.2.1.31.1.1.1.2`
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:.1.3.6.1.2.1.2.2.1.2 -op:.1.3.6.1.2.1.2.2.1.3`

    На выходе словарь вида:
    ```
    {
    "results_list": [
        {
            "logical_interface_id": "49",
            "port_name": "gi1/0/1"
        },
        ],
        "count": int,
        "error": str
    }
    ```
    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.
    """
    # Запрашиваем сырые данные от хоста
    ret_data = await get_oid_from_to(query)
    if ret_data["error"] is not None:
        return ret_data

    return extract_port_and_port_name(ret_data)


@router.post("/query/arp", summary="Запрос соответствий мак-адресов и IP-адресов.")
async def query_arp_table(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос соответствий мак-адресов и IP-адресов. По портам.

    Аналог запросов:
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:1.3.6.1.2.1.4.22.1.2 -op:1.3.6.1.2.1.4.22.1.3`

    На выходе словарь вида:
    ```
    {
      "results_list": [
        {
          "logical_interface_id": "100004",
          "ip_addr": "10.0.1.4",
          "mac": "62:13:a2:97:84:00"
        },
        ],
        "count": int,
        "error": str
    }
    ```
    Обязательно проверять значение ключа error. Если оно не null - результатам верить нельзя.
    """
    # Запрашиваем сырые данные от хоста
    ret_data = await get_oid_from_to(query)
    if ret_data["error"] is not None:
        return ret_data

    return extract_arp_table(ret_data)


@router.post("/query/info_mac", summary="Запрос MAC адреса устройства")
async def query_info_mac(query: QueryOID, user: UserData4Auth = Depends(get_current_user)) -> ResultQueryOID:
    """
    Запрос MAC адреса устройства.

    Аналог запросов:
    * `SnmpWalk -csv -v:2c -c:public -r:host -os:1.0.8802.1.1.2.1.3.2 -op:1.0.8802.1.1.2.1.3.3`

    """
    ret_data = await get_oid_from_to(query)

    if ret_data["error"] is not None:
        return ret_data["error"]

    return extract_mac_addr(ret_data)
