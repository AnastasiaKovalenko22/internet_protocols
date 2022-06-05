import argparse
import socket
import pickle
import time
from dns_packet import DNSPacket
import struct


class DNS:
    def __init__(self, port, forwarder, ttl):
        self.port = port
        self.local_address = '127.0.0.1'
        self.forwarder = forwarder
        self.ttl = ttl

    def run_server(self):
        cache = DNSCache(self.ttl)
        while True:
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.bind((self.local_address, self.port))
                server.recvfrom(1024)
                server.recvfrom(1024)
                data, address = server.recvfrom(1024)
                request_processing = DNSPacket(data)
                info_from_cache = cache.get((request_processing.domain, request_processing.question_type))
                if info_from_cache:
                    print("answer from cache")
                    response = request_processing.get_response(info_from_cache)
                    server.sendto(response, address)
                else:
                    print("answer from server")
                    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    dns_socket.sendto(data, (self.forwarder, self.port))
                    dns_data, rem_address = dns_socket.recvfrom(1024)
                    server.sendto(dns_data, address)
                    request_processing = DNSPacket(dns_data)
                    cache.add(request_processing.domain, request_processing.question_type,
                              request_processing.info)
            except KeyboardInterrupt:
                break
            finally:
                cache.save()


class DNSCache:
    def __init__(self, ttl):
        self.cache = dict()
        self.ttl = ttl
        try:
            with open('cache.txt', 'rb') as file:
                actual_cache = pickle.load(file)
                updated_cache = dict()
                for key, value in actual_cache.items():
                    old_records = []
                    records_time = value[1]
                    list_of_records = value[0]
                    for record in list_of_records:
                        if records_time + self.ttl < time.time():
                            old_records.append(record)
                    for rec in old_records:
                        list_of_records.remove(rec)
                    if list_of_records:
                        updated_cache[key] = (list_of_records, records_time)
                self.cache = updated_cache.copy()
        except IOError:
            with open('cache.txt', 'w'):
                print('created cache')

    def add(self, name, type_ask, info):
        self.cache[(name, type_ask)] = (info, time.time())
        self.save()

    def get(self, key):
        old_records = []
        if key in self.cache:
            value = self.cache[key]
            records_time = value[1]
            list_of_records = value[0]
            for record in list_of_records:
                if records_time + self.ttl < time.time():
                    old_records.append(record)
            for old_rec in old_records:
                list_of_records.remove(old_rec)
            return list_of_records
        return None

    def save(self):
        with open('cache.txt', 'wb') as file:
            pickle.dump(self.cache, file)


def get_args():
    parser = argparse.ArgumentParser(description="DNS server")
    parser.add_argument(
        "forwarder",
        default="8.8.8.8",
        help="Forwarder IP address")
    parser.add_argument(
        "--port",
        help="Port",
        default=53, type=int)
    parser.add_argument(
        "--ttl",
        help="Time to life data in cache",
        default=3600, type=int)
    args = parser.parse_args()
    return args


class DNSPacket:
    def __init__(self, data):
        self.data = data
        self.header = struct.unpack(">6H", self.data[:12])
        flags = bin(self.header[1])
        self.flags = '0' * (16 - len(flags) + 2) + str(flags)[2:]
        self.answer = self.flags[0]
        self.info = None
        self.domain, end_position = self.get_domain(12, 255)
        self.question_type, self.question_class = struct.unpack(">HH", self.data[end_position + 1:end_position + 5])
        end_position += 5
        self.length_of_question = end_position
        if self.answer:
            offset_first, self.rrs_answer = self.get_records(end_position, 3)
            offset_second, self.rrs_authority = self.get_records(offset_first, 4)
            self.rrs_additional = self.get_records(offset_second, 5)[1]
            self.info = self.rrs_answer + self.rrs_authority + self.rrs_additional

    def get_domain(self, offset, domain_length_in_bytes):
        state = 0
        domain_string = ''
        expected_length = 0
        domain_parts = []
        x = 0
        end_position = offset
        data = self.data[offset:offset + domain_length_in_bytes]
        has_offset = False
        for byte in data:
            if not byte:
                break
            if has_offset:
                has_offset = False
                end_position += 1
                continue
            if str(bin(byte))[2:4] == "11" and len(str(bin(byte))) == 10:
                name_offset = struct.unpack(">B", self.data[end_position + 1:end_position + 2])[0]
                has_offset = True
                domain, _ = self.get_domain(name_offset, 255)
                domain_parts.append(domain)
            else:
                if state == 1:
                    domain_string += chr(byte)
                    x += 1
                    if expected_length == x:
                        domain_parts.append(domain_string)
                        domain_string = ''
                        state = 0
                        x = 0
                else:
                    state = 1
                    expected_length = byte
            end_position += 1
        domain = ".".join(domain_parts)
        return domain, end_position

    def get_records(self, start_index, index_in_header):
        list_of_records = []
        offset = start_index
        original_offset = offset
        has_offset = False
        for i in range(self.header[index_in_header]):
            is_off = struct.unpack(">B", self.data[offset:offset + 1])
            if str(bin(is_off[0]))[2:4] == "11":
                original_offset = offset + 2
                offset = struct.unpack(">B", self.data[offset + 1:offset + 2])[0]
                has_offset = True
            domain, end_position = self.get_domain(offset, 255)
            offset = end_position
            if has_offset:
                offset = original_offset
            record_type, record_class, record_ttl, record_length = struct.unpack(">2HIH",
                                                                                 self.data[offset: offset + 10])
            offset += 10
            if record_type == 1:  # A
                domain_ip = struct.unpack(">4B", self.data[offset:offset + 4])
                offset += 4
                list_of_records.append((domain, record_type, record_ttl, 4, domain_ip))
            elif record_type == 2:  # NS
                dns_name, end_name_position = self.get_domain(offset, record_length)
                list_of_records.append((domain, record_type, record_ttl, end_name_position - offset, dns_name))
                offset = end_name_position
            else:
                offset += record_length
            has_offset = False
        return offset, list_of_records

    @staticmethod
    def pack_domain(domain):
        if type(domain) == str:
            names = domain.split(".")
        else:
            names = (domain.decode('utf8')).split(".")
        res = []
        for name in names:
            res.append(len(name))
            for letter in name:
                res.append(ord(letter))
        res.append(0)
        return struct.pack(">" + str(len(res)) + "B", *res), len(res)

    @staticmethod
    def pack_ipv6(domain):
        parts = (domain.decode('utf8')).split(":")
        res = []
        for part in parts:
            res.append(len(part))
            for symbol in part:
                res.append(symbol)
        return struct.pack(">" + str(len(res)) + "B", *res), len(res)

    def get_response(self, info):
        header = list(self.header)
        header[1] += 32768
        header[3] = len(info)
        question = self.data[12:self.length_of_question]
        question_and_answer = question
        if self.question_type == 1:
            for record in info:
                offset = struct.pack(">2B", 192, 12)
                question_and_answer += (offset + struct.pack(">HHIH", record[1], 1, record[2], 4) +
                                        struct.pack(">4B", *record[4]))
        if self.question_type == 2:
            for record in info:
                offset = struct.pack(">2B", 192, 12)
                pack_name = self.pack_domain(record[4])
                question_and_answer += (offset + struct.pack(">HHIH", record[1], 1, record[2], pack_name[1]) +
                                        pack_name[0])
        if self.question_type == 12:
            for record in info:
                offset = struct.pack(">2B", 192, 12)
                pack_ip = self.pack_ipv6(record[4])
                question_and_answer += (offset + struct.pack(">HHIH", record[1], 1, record[2], pack_ip[1]) +
                                        pack_ip[0])

        response = struct.pack(">6H", *header) + question_and_answer
        return response


if __name__ == '__main__':
    arguments = get_args()
    dns_server = DNS(arguments.port, arguments.forwarder, arguments.ttl)
    dns_server.run_server()
