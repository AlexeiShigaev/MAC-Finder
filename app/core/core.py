import asyncio
import copy
import traceback
from pprint import pprint
from typing import List, Dict, Optional

from app.core.models import NewDevice, DeviceInfo, PortInfo, InternalIP
from app.core.utils import is_it_ipv4, is_it_mac_addr
from app.database import motorchik
from app.snmp.models import QueryOID, ResultQueryOID
from app.snmp.router import (
    query_info_ip,
    query_info,
    query_mac_vlan_port,
    query_ports,
    query_arp_table,
    query_info_mac
)


#################################################################
# Секция вспомогательных инструментов
#################################################################
def search_mac_address(mac_ip: dict, where_dict: Dict[str, DeviceInfo]):
    """
    mac_ip: {"mac": ""68:13:e2:85:c2:80, "ip": "10.20.30.41"}
    """
    # print("search_mac_address: {}".format(mac_ip))
    results = {
        mac_ip["ip"]: {
            "mac": mac_ip["mac"],
            "devices": {}
        }
    }
    for host, dev in where_dict.items():
        for port, port_data in dev.ports.items():
            if mac_ip["mac"] in port_data.macs \
                    and mac_ip["ip"] != host:
                results[mac_ip["ip"]]["devices"].update({dev.host: {
                    "port": port,
                    "port_name": port_data.name,
                    "port_macs_counter": len(port_data.macs)
                }
                })
    return results


def generate_mac_ip_pair(
        query: str,
        where_mac_ip_dict: dict,
        where_device_dict: Dict[str, DeviceInfo]
):
    query = query.lower()
    if is_it_ipv4(query):
        for mac, ip_list in where_mac_ip_dict.items():
            if query in ip_list:
                return search_mac_address({
                    "mac": mac, "ip": ip_list[0]
                }, where_device_dict)
    elif is_it_mac_addr(query) and (query in where_mac_ip_dict.keys()):
        return search_mac_address({
            "mac": query, "ip": where_mac_ip_dict[query][0] if len(where_mac_ip_dict[query]) else "?"
        }, where_device_dict)
    else:
        return None


def construct_devices_tree(devices: dict):
    sorted_devices = sorted(
        devices.values(),
        key=lambda item: item["device_macs_counter"],
        reverse=True
    )

    dev = devices.pop(sorted_devices[0]["host"])
    tree = {sorted_devices[0]["host"]: dev}

    for port, data in dev["ports"].items():
        # Ситуация однозначна, на одном порту одно устройство
        if len(data["links"]) == 1:
            el = devices.pop(data["links"][0])
            # и воткнуть линк в элемент узла уровнем выше
            dev["ports"][port].update(
                {"uplink": {el["host"]: el}}
            )
        if not len(devices):
            return tree
    # Первый проход вытащил листья.
    # Вторым проходом (поскольку нет больше лишних узлов в исходном списке) работаем по длинным веткам.
    for port, data in dev["ports"].items():
        if len(data["links"]) > 1:
            # В ситуации когда на одном порту несколько линков, два важных момента:
            # 1. Ближе к корню то устройство, общее количество маков на котором больше.
            # 2. Устройство на котором линки только на одном порту - крайнее (лист дерева),
            #    соответственно, если есть, например, два линка и они на разных портах -
            #    то такое устройство - промежуточное. Правда это немного сложнее в реализации.
            sub_tree = construct_devices_tree(devices)
            dev["ports"][port].update(
                {"uplink": sub_tree}
            )
        if not len(devices):
            return tree

    return tree


#################################################################
# Секция инструментов для эндпоинтов
#################################################################
class CoreManager:
    device_dict: Dict[str, DeviceInfo] = {}
    device_tree = {}
    mac_ip_dict = {}

    @classmethod
    async def update_device_info(cls, dev: NewDevice):
        # pprint("start Update_device_info. dev: {}".format(dev))

        # Содержит в себе информацию, вынутую через SNMP из устройства
        device = DeviceInfo(host=dev.host)

        # разворачиваем в строку именование, комментарии, производителя.
        info: ResultQueryOID = await query_info(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=dev.info_oid_start, oid_stop=dev.info_oid_stop
        ))
        device.info = "<br>".join(
            [el for elem in info.results_list for el in elem.values() if not el == ""]
        )

        # а какие порты есть на устройстве?
        ports: ResultQueryOID = await query_ports(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=dev.ports_oid_start, oid_stop=dev.ports_oid_stop
        ))
        for elem in ports.results_list:
            device.ports.update({
                elem["logical_interface_id"]: PortInfo(name=elem["port_name"])
            })
        # print(device.ports)

        # внутренние IP адреса
        internal_ips = await query_info_ip(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=dev.internal_ip_oid_start, oid_stop=dev.internal_ip_oid_stop
        ))
        [device.internal_ip.update({el["ipAdEntAddr"]: InternalIP(**el)}) for el in internal_ips.results_list]

        # С MAC-ами-VLAN-ами немного сложнее
        mac_vlan: ResultQueryOID = await query_mac_vlan_port(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=dev.macs_oid_start, oid_stop=dev.macs_oid_stop
        ))
        device.device_macs_counter = mac_vlan.count

        for elem in mac_vlan.results_list:
            if elem["logical_interface_id"] in device.ports:
                device.ports[elem["logical_interface_id"]].macs.update(
                    {elem["mac"]: elem["vlan"]}
                )

            if elem["mac"] not in cls.mac_ip_dict:
                cls.mac_ip_dict.update({
                    elem["mac"]: []  # Здесь будет IP-addr, если будет
                })

        # arp-table, если есть
        arp: ResultQueryOID = await query_arp_table(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=dev.arp_oid_start, oid_stop=dev.arp_oid_stop
        ))
        for elem in arp.results_list:
            cls.mac_ip_dict.setdefault(elem["mac"], [])
            # если уже добавляли такой IP, то незачем делать дубли
            if elem["ip_addr"] not in cls.mac_ip_dict[elem["mac"]]:
                cls.mac_ip_dict[elem["mac"]].append(elem["ip_addr"])

        # mac адреса по портам
        internal_macs: ResultQueryOID = await query_info_mac(QueryOID(
            host=dev.host, port=dev.port, community=dev.community, snmp_ver=dev.snmp_ver,
            oid_start=".1.3.6.1.2.1.2.2.1.6", oid_stop="1.3.6.1.2.1.2.2.1.7"
        ))
        ports = internal_macs.results_list[0]["ports"]
        for i_face in device.internal_ip.values():
            i_face.ifPhyAddress = ports[i_face.ipAdEntIfIndex]
            cls.mac_ip_dict.setdefault(i_face.ifPhyAddress, [])
            if i_face.ipAdEntAddr not in cls.mac_ip_dict[i_face.ifPhyAddress]:
                cls.mac_ip_dict[i_face.ifPhyAddress].append(i_face.ipAdEntAddr)

        # Добавим устройство
        cls.device_dict.update({device.host: device})
        print("опрос устройства окончен успешно.")
        return

    @classmethod
    async def update_device_tree(cls):
        loop = asyncio.get_running_loop()
        tasks = []

        # вынимаю из коллекции все устройства, по очереди опрашиваю, формирую список устройств и коллекцию маков
        cursor = motorchik.find("devices", None)
        devices = await cursor.to_list(length=None)
        if not len(devices):
            print("!!! Empty devices list. Please, configure devices.")
            return

        for device in devices:
            tasks.append(
                loop.create_task(
                    cls.update_device_info(NewDevice(**device))
                )
            )

        results = await asyncio.gather(*tasks)

        # Выясним встречные линки устройств
        links_dict = {}

        print("\nНа каких портах видны устройства")
        for dev_ip, dev_data in cls.device_dict.items():
            res = search_mac_address(
                {"mac": dev_data.internal_ip[dev_ip].ifPhyAddress, "ip": dev_data.internal_ip[dev_ip].ipAdEntAddr},
                cls.device_dict
            )

            for ip, data in res[dev_ip]["devices"].items():
                links_dict.setdefault(ip, {
                    "host": cls.device_dict[ip].host,
                    "device_macs_counter": cls.device_dict[ip].device_macs_counter,
                    "ports": {}
                })
                links_dict[ip]["ports"].setdefault(data["port"], {
                    "port_name": data["port_name"], "port_macs_counter": data["port_macs_counter"], "links": []
                })
                links_dict[ip]["ports"][data["port"]]["links"].append(dev_ip)

        cls.device_tree = construct_devices_tree(links_dict)

        print("update_device_tree finished")


#################################################################
# Секция запуска ядра
#################################################################
class Core:
    state: int = 1

    @classmethod
    def update(cls):
        cls.state = 2

    @classmethod
    def stop(cls):
        cls.state = 0

    @classmethod
    def updated(cls):
        cls.state = 1

    @classmethod
    def is_in_progress(cls) -> bool:
        return True if cls.state == 2 else False


async def run_core():
    Core.update()
    sleep_time = 2
    while True:
        # print("Core tik")
        await asyncio.sleep(sleep_time)
        sleep_time = 5
        if not Core.state:
            # не забыть погасить свет
            print("run_core ends")
            break
        elif Core.state == 2:
            print("start_update_device_tree")
            try:
                await CoreManager.update_device_tree()
            except Exception as e:
                print("run_core: {}".format(e))
                traceback.print_exc()
            Core.updated()
