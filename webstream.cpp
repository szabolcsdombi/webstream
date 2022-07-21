#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <map>

#define HTTP_101 "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
#define HTTP_404 "HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
#define HTTP_200 "HTTP/1.1 200 OK\r\nConnection: close\r\n"

void sec_websocket_accept(const void * src, void * dst) {
    unsigned char * const salt = (unsigned char *)src;
    char * const result = (char *)dst;

    const char * const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    unsigned block0[16] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x32353845, 0x41464135,
        0x2d453931, 0x342d3437, 0x44412d39, 0x3543412d, 0x43354142, 0x30444338, 0x35423131, 0x80000000,
    };
    unsigned block1[16] = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x000001e0,
    };

    unsigned a = 0x67452301;
    unsigned b = 0xEFCDAB89;
    unsigned c = 0x98BADCFE;
    unsigned d = 0x10325476;
    unsigned e = 0xC3D2E1F0;
    unsigned ta, tb, tc, td, te;

    block0[0] = salt[0] << 24 | salt[1] << 16 | salt[2] << 8 | salt[3];
    block0[1] = salt[4] << 24 | salt[5] << 16 | salt[6] << 8 | salt[7];
    block0[2] = salt[8] << 24 | salt[9] << 16 | salt[10] << 8 | salt[11];
    block0[3] = salt[12] << 24 | salt[13] << 16 | salt[14] << 8 | salt[15];
    block0[4] = salt[16] << 24 | salt[17] << 16 | salt[18] << 8 | salt[19];
    block0[5] = salt[20] << 24 | salt[21] << 16 | salt[22] << 8 | salt[23];

    #define rol(value, bits) (((value)<<(bits))|((value)>>(32-(bits))))
    #define blk(i) (block[i&15]=rol(block[(i+13)&15]^block[(i+8)&15]^block[(i+2)&15]^block[i&15],1))
    #define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+block[i]+0x5A827999+rol(v,5);w=rol(w,30);
    #define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
    #define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
    #define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
    #define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

    #define block block0
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    #undef block

    a += 0x67452301;
    b += 0xEFCDAB89;
    c += 0x98BADCFE;
    d += 0x10325476;
    e += 0xC3D2E1F0;

    ta = a;
    tb = b;
    tc = c;
    td = d;
    te = e;

    #define block block1
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    #undef block

    #undef rol
    #undef blk
    #undef R0
    #undef R1
    #undef R2
    #undef R3
    #undef R4

    a += ta;
    b += tb;
    c += tc;
    d += td;
    e += te;

    result[0] = table[a >> 26 & 63];
    result[1] = table[a >> 20 & 63];
    result[2] = table[a >> 14 & 63];
    result[3] = table[a >> 8 & 63];
    result[4] = table[a >> 2 & 63];
    result[5] = table[(a << 4 & 48) | (b >> 28 & 15)];
    result[6] = table[b >> 22 & 63];
    result[7] = table[b >> 16 & 63];
    result[8] = table[b >> 10 & 63];
    result[9] = table[b >> 4 & 63];
    result[10] = table[(b << 2 & 60) | (c >> 30 & 3)];
    result[11] = table[c >> 24 & 63];
    result[12] = table[c >> 18 & 63];
    result[13] = table[c >> 12 & 63];
    result[14] = table[c >> 6 & 63];
    result[15] = table[c & 63];
    result[16] = table[d >> 26 & 63];
    result[17] = table[d >> 20 & 63];
    result[18] = table[d >> 14 & 63];
    result[19] = table[d >> 8 & 63];
    result[20] = table[d >> 2 & 63];
    result[21] = table[(d << 4 & 48) | (e >> 28 & 15)];
    result[22] = table[e >> 22 & 63];
    result[23] = table[e >> 16 & 63];
    result[24] = table[e >> 10 & 63];
    result[25] = table[e >> 4 & 63];
    result[26] = table[e << 2 & 60];
    result[27] = '=';
}

int new_client_id() {
    static int client_id = 1;
    return client_id++;
}

enum PacketType {
    PT_INVALID,
    PT_CONNECTED,
    PT_DISCONNECTED,
    PT_TEXT_PAYLOAD,
    PT_BINARY_PAYLOAD,
};

struct Packet {
    PacketType type;
    int client;
    int size;
    char * data;
};

struct Client {
    int id;
    int sock;
    int upgraded;
    int requested;
    int input_size;
    int output_size;
    char * input_buffer;
    char * output_buffer;
    Packet packet;
};

int epoll;
int wssin[2];
int wssout[2];

std::map<int, Client *> client_map;

sockaddr_in server_addr = {};
void * accept_socket_id = malloc(1);
void * message_pipe_id = malloc(1);

PyObject * event_names[8];

int client_response(Client * client) {
    if (client->requested) {
        return -1;
    }

    if (client->input_size > 4 && !memcmp(client->input_buffer + client->input_size - 4, "\r\n\r\n", 4)) {
        client->input_buffer[client->input_size - 4] = 0;
        client->requested = true;

        char * ptr = client->input_buffer;
        int state = 0;

        for (int i = 0; i < client->input_size; ++i) {
            if (ptr[i] == '\n') {
                state = 1;
            }
            if (ptr[i] == ':' && state == 1) {
                state = 2;
            }
            if (ptr[i] >= 'A' && ptr[i] <= 'Z' && state == 1) {
                ptr[i] += 'z' - 'Z';
            }
        }

        char * key = strstr(client->input_buffer, "sec-websocket-key:");

        if (!key) {
            char result[] = HTTP_404 "Content-Type: text/html\r\nContent-Length: 0\r\n\r\n";
            client->output_buffer = (char *)malloc(90);
            memcpy(client->output_buffer, result, 90);
            client->output_size = 90;

            epoll_event event = {EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP, client};
            epoll_ctl(epoll, EPOLL_CTL_MOD, client->sock, &event);

            free(client->input_buffer);
            client->input_buffer = NULL;
            client->input_size = 0;
            return 0;
        }

        key = key + 18;
        while (*key == ' ') {
            key += 1;
        }

        if (client->input_size - (key - client->input_buffer) < 24) {
            return -1;
        }

        if (!strtok(client->input_buffer, " ")) {
            return -1;
        }

        char * path = strtok(NULL, " ");
        if (!path) {
            return -1;
        }

        char result[] = HTTP_101 "Sec-WebSocket-Accept: ____________________________\r\n\r\n";
        sec_websocket_accept(key, result + 97);
        client->output_buffer = (char *)malloc(129);
        memcpy(client->output_buffer, result, 129);
        client->output_size = 129;

        epoll_event event = {EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP, client};
        epoll_ctl(epoll, EPOLL_CTL_MOD, client->sock, &event);

        Packet packet = {};
        packet.type = PT_CONNECTED;
        packet.client = client->id;
        packet.size = strlen(path);
        packet.data = (char *)malloc(packet.size);
        memcpy(packet.data, path, packet.size);

        free(client->input_buffer);
        client->input_buffer = NULL;
        client->input_size = 0;
        client->upgraded = true;

        write(wssin[1], &packet, sizeof(Packet));
    }

    return 0;
}

int client_parse(Client * client) {
    int left = client->input_size;

    while (true) {
        uint8_t * ptr = (uint8_t *)client->input_buffer + client->input_size - left;

        int head = (left < 2 ? 2 : ptr[1] == 255 ? 10 : ptr[1] == 254 ? 4 : 2) + 4;
        if (left < head) {
            break;
        }

        int size = ptr[1] == 255 ? (ptr[6] << 24 | ptr[7] << 16 | ptr[8] << 8 | ptr[9]) : ptr[1] == 254 ? (ptr[2] << 8 | ptr[3]) : ptr[1] - 128;
        if (left < head + size) {
            break;
        }

        uint8_t opcode = ptr[0] & 15;
        uint8_t fin = ptr[0] & 0x80;

        if (opcode == 8) {
            return -1;
        }

        if (opcode == 0 || opcode == 1 || opcode == 2) {
            uint8_t * mask = ptr + head - 4;
            uint8_t * payload = ptr + head;
            for (int i = 0; i < size; ++i) {
                payload[i] ^= mask[i & 3];
            }

            if (opcode) {
                if (client->packet.size) {
                    return -1;
                }
                client->packet.type = opcode == 1 ? PT_TEXT_PAYLOAD : PT_BINARY_PAYLOAD;
                client->packet.client = client->id;
                client->packet.size = size;
                client->packet.data = (char *)malloc(size);
                memcpy(client->packet.data, payload, size);
            } else {
                if (!client->packet.size) {
                    return -1;
                }
                client->packet.data = (char *)realloc(client->packet.data, client->packet.size + size);
                memcpy(client->packet.data + client->packet.size, payload, size);
                client->packet.size += size;
            }
        }

        if (fin) {
            write(wssin[1], &client->packet, sizeof(Packet));
            client->packet.size = 0;
            client->packet.data = NULL;
        }

        left -= head + size;
    }

    int processed = client->input_size - left;

    if (processed) {
        if (processed == client->input_size) {
            free(client->input_buffer);
            client->input_buffer = NULL;
            client->input_size = 0;
        } else {
            memcpy(client->input_buffer, client->input_buffer + processed, client->input_size - processed);
            client->input_buffer = (char *)realloc(client->input_buffer, client->input_size - processed);
            client->input_size -= processed;
        }
    }

    return 0;
}

int client_read(Client * client) {
    static char chunk[1024 * 1024];
    int chunk_size = read(client->sock, chunk, sizeof(chunk));
    if (chunk_size <= 0) {
        return -1;
    }

    client->input_buffer = (char *)realloc(client->input_buffer, client->input_size + chunk_size);
    memcpy(client->input_buffer + client->input_size, chunk, chunk_size);
    client->input_size += chunk_size;

    if (!client->upgraded) {
        if (client_response(client)) {
            return -1;
        }
    } else {
        if (client_parse(client)) {
            return -1;
        }
    }

    return 0;
}

int client_write(Client * client) {
    int chunk_size = write(client->sock, client->output_buffer, client->output_size);
    if (chunk_size <= 0) {
        return -1;
    }

    if (chunk_size == client->output_size) {
        free(client->output_buffer);
        client->output_buffer = NULL;
        client->output_size = 0;
        epoll_event event = {EPOLLIN | EPOLLRDHUP | EPOLLHUP, client};
        epoll_ctl(epoll, EPOLL_CTL_MOD, client->sock, &event);
    } else {
        memcpy(client->output_buffer, client->output_buffer + chunk_size, client->output_size - chunk_size);
        client->output_buffer = (char *)realloc(client->output_buffer, client->output_size - chunk_size);
        client->output_size -= chunk_size;
    }

    return 0;
}

void remove_client(Client * client) {
    if (client->input_buffer) {
        free(client->input_buffer);
    }
    if (client->output_buffer) {
        free(client->output_buffer);
    }
    if (client->packet.data) {
        free(client->packet.data);
    }
    if (client->upgraded) {
        Packet packet = {};
        packet.type = PT_DISCONNECTED;
        packet.client = client->id;
        write(wssin[1], &packet, sizeof(Packet));
    }
    client_map.erase(client->id);
    epoll_ctl(epoll, EPOLL_CTL_DEL, client->sock, NULL);
    close(client->sock);
    free(client);
}

void client_deliver(Client * client, Packet * packet) {
    bool idle = !client->output_size;
    int head = packet->size > 65535 ? 10 : packet->size > 125 ? 4 : 2;
    client->output_buffer = (char *)realloc(client->output_buffer, client->output_size + packet->size + head);
    char * ptr = client->output_buffer + client->output_size;
    ptr[0] = packet->type == PT_BINARY_PAYLOAD ? 0x82 : 0x81;
    ptr[1] = head == 10 ? 127 : head == 4 ? 126 : (char)packet->size;
    if (head == 10) {
        ptr[2] = 0;
        ptr[3] = 0;
        ptr[4] = 0;
        ptr[5] = 0;
        ptr[6] = (char)(packet->size >> 24 & 0xff);
        ptr[7] = (char)(packet->size >> 16 & 0xff);
        ptr[8] = (char)(packet->size >> 8 & 0xff);
        ptr[9] = (char)(packet->size >> 0 & 0xff);
    }
    if (head == 4) {
        ptr[2] = (char)(packet->size >> 8 & 0xff);
        ptr[3] = (char)(packet->size >> 0 & 0xff);
    }
    memcpy(client->output_buffer + client->output_size + head, packet->data, packet->size);
    client->output_size += packet->size + head;
    if (idle) {
        epoll_event event = {EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP, client};
        epoll_ctl(epoll, EPOLL_CTL_MOD, client->sock, &event);
    }
}

void * wss_worker(void *) {
    epoll = epoll_create(1);

    int accept_sock = socket(AF_INET, SOCK_STREAM, 0);

    int reuse = 1;
    setsockopt(accept_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    bind(accept_sock, (sockaddr *)&server_addr, sizeof(server_addr));
    listen(accept_sock, 5);
    fcntl(accept_sock, F_SETFD, fcntl(accept_sock, F_GETFD, 0) | O_NONBLOCK);

    epoll_event event1 = {EPOLLIN, accept_socket_id};
    epoll_ctl(epoll, EPOLL_CTL_ADD, accept_sock, &event1);

    epoll_event event2 = {EPOLLIN, message_pipe_id};
    epoll_ctl(epoll, EPOLL_CTL_ADD, wssout[0], &event2);

    while (true) {
        const int max_events = 128;
        epoll_event events[max_events];
        int num_events = epoll_wait(epoll, events, max_events, -1);

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.ptr == accept_socket_id) {
                sockaddr_in client_addr = {};
                unsigned socklen = sizeof(client_addr);
                int client_sock = accept(accept_sock, (sockaddr *)&client_addr, &socklen);
                fcntl(client_sock, F_SETFD, fcntl(client_sock, F_GETFD, 0) | O_NONBLOCK);

                Client * client = (Client *)malloc(sizeof(Client));
                memset(client, 0, sizeof(Client));
                client->id = new_client_id();
                client->sock = client_sock;
                client->upgraded = false;
                client->requested = false;

                client_map[client->id] = client;

                epoll_event event = {EPOLLIN | EPOLLRDHUP | EPOLLHUP, client};
                epoll_ctl(epoll, EPOLL_CTL_ADD, client_sock, &event);
                continue;
            }

            if (events[i].data.ptr == message_pipe_id) {
                Packet packet = {};
                read(wssout[0], &packet, sizeof(Packet));
                if (packet.client > 0) {
                    std::map<int, Client *>::iterator it = client_map.find(packet.client);
                    if (it != client_map.end()) {
                        client_deliver(it->second, &packet);
                    }
                } else {
                    for (std::map<int, Client *>::iterator it = client_map.begin(); it != client_map.end(); ++it) {
                        client_deliver(it->second, &packet);
                    }
                }
                free(packet.data);
                continue;
            }

            Client * client = (Client *)events[i].data.ptr;

            if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
                remove_client(client);
                continue;
            }

            if (events[i].events & EPOLLIN) {
                if (client_read(client)) {
                    remove_client(client);
                    continue;
                }
            }

            if (events[i].events & EPOLLOUT) {
                if (client_write(client)) {
                    remove_client(client);
                    continue;
                }
            }
        }
    }

    return NULL;
}

PyObject * meth_init(PyObject * self, PyObject * args, PyObject * kwargs) {
    const char * keywords[] = {"host", "port", NULL};

    const char * host;
    int port;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sI", (char **)keywords, &host, &port)) {
        return NULL;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(host);
    server_addr.sin_port = htons(port);

    pthread_t wss_thread;
    pipe2(wssin, O_DIRECT | O_NONBLOCK);
    pipe2(wssout, O_DIRECT | O_NONBLOCK);
    pthread_create(&wss_thread, NULL, wss_worker, NULL);
    Py_RETURN_NONE;
}

PyObject * meth_send(PyObject * self, PyObject * args, PyObject * kwargs) {
    const char * keywords[] = {"data", "client", "binary", NULL};

    Py_buffer view = {};
    int client = 0;
    int binary = false;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|Ip", (char **)keywords, &view, &client, &binary)) {
        return NULL;
    }

    Packet packet = {};
    packet.type = binary ? PT_BINARY_PAYLOAD : PT_TEXT_PAYLOAD;
    packet.client = client;
    packet.size = (int)view.len;
    packet.data = (char *)malloc(view.len);
    memcpy(packet.data, view.buf, view.len);
    write(wssout[1], &packet, sizeof(Packet));
    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

PyObject * meth_recv(PyObject * self) {
    Packet packet = {};
    int chunk_size = read(wssin[0], &packet, sizeof(Packet));
    if (chunk_size <= 0) {
        Py_RETURN_NONE;
    }

    Py_INCREF(event_names[packet.type]);
    PyObject * res = PyTuple_New(3);
    PyTuple_SET_ITEM(res, 0, PyLong_FromLong(packet.client));
    PyTuple_SET_ITEM(res, 1, event_names[packet.type]);
    PyTuple_SET_ITEM(res, 2, PyBytes_FromStringAndSize(packet.data, packet.size));
    if (packet.data) {
        free(packet.data);
    }

    return res;
}

PyMethodDef module_methods[] = {
    {"init", (PyCFunction)meth_init, METH_VARARGS | METH_KEYWORDS, NULL},
    {"send", (PyCFunction)meth_send, METH_VARARGS | METH_KEYWORDS, NULL},
    {"recv", (PyCFunction)meth_recv, METH_NOARGS, NULL},
    {},
};

PyModuleDef module_def = {PyModuleDef_HEAD_INIT, "webstream", NULL, -1, module_methods};

extern "C" PyObject * PyInit_webstream() {
    PyObject * module = PyModule_Create(&module_def);
    event_names[PT_CONNECTED] = PyUnicode_FromString("connected");
    event_names[PT_DISCONNECTED] = PyUnicode_FromString("disconnected");
    event_names[PT_BINARY_PAYLOAD] = PyUnicode_FromString("binary");
    event_names[PT_TEXT_PAYLOAD] = PyUnicode_FromString("text");
    return module;
}
