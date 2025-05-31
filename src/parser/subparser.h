#ifndef SUBPARSER_H_INCLUDED
#define SUBPARSER_H_INCLUDED

#include <string>

#include "config/proxy.h"

enum class ConfType
{
    Unknow,
    SS,
    SSR,
    V2Ray,
    SSConf,
    SSTap,
    Netch,
    SOCKS,
    HTTP,
    SUB,
    Local
};

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &sni, const std::vector<std::string> &alpnList, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &protocol, const std::string &method, const std::string &obfs, const std::string &password, const std::string &obfsparam, const std::string &protoparam, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &method, const std::string &plugin, const std::string &pluginopts, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, bool tls, tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &network, const std::string &host, const std::string &path, const std::string &fp, const std::string &sni, const std::vector<std::string> &alpnList, bool tlssecure, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "");
void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &obfs, const std::string &host, uint16_t version = 0, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void hysteriaConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &protocol, const std::string &obfs_protocol, const std::string &up, const std::string &up_speed, const std::string &down, const std::string &down_speed, const std::string &auth, const std::string &auth_str, const std::string &obfs, const std::string &sni, const std::string &fingerprint, const std::string &ca, const std::string &ca_str, const std::string &recv_window_conn, const std::string &recv_window, const std::string &disable_mtu_discovery, const std::string &hop_interval, const std::string &alpn, tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void hysteria2Construct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &ports, const std::string &up, const std::string &down, const std::string &password, const std::string &obfs, const std::string &obfs_password, const std::string &sni, const std::string &fingerprint, const std::string &alpn, const std::string &ca, const std::string &caStr, const std::string &cwnd, const std::string &hop_interval, tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &flow, const std::string &mode, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &pkd, const std::string &sid, const std::string &fp, const std::string &sni, const std::vector<std::string> &alpnList, const std::string &packet_encoding, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(), const std::string &underlying_proxy = "", tribool v2ray_http_upgrade = tribool());
void TUICConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &uuid, const std::string &password, const std::string &ip, const std::string &heartbeatinterval, const std::string &requesttimeout, const std::string &udprelaymode, const std::string &congestioncontroller, const std::string &token, const std::string &maxudprelaypacketsize, const std::string &fastopen, const std::string &maxopenstreams, const std::string &sni, const std::string &alpn, tribool disablesni = tribool(), tribool reducertt = tribool(), tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), const std::string &underlying_proxy = "");
void anyTLSConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &port, const std::string &password, const std::string &host, const std::vector<String> &AlpnList, const std::string &fingerprint, const std::string &sni, tribool udp = tribool(), tribool tfo = tribool(), tribool scv = tribool(), tribool tls13 = tribool(),const std::string& underlying_proxy="",uint16_t idleSessionCheckInterval=30,uint16_t idleSessionTimeout=30,uint16_t minIdleSession=0);
void mieruConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &port, const std::string &password, const std::string &host, const std::string &ports, const std::string &username,const std::string &multiplexing, const std::string &transfer_protocol, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string &underlying_proxy);

void explodeVmess(std::string vmess, Proxy &node);
void explodeSSR(std::string ssr, Proxy &node);
void explodeSS(std::string ss, Proxy &node);
void explodeTrojan(std::string trojan, Proxy &node);
void explodeHysteria(std::string hysteria, Proxy &node);
void explodeHysteria2(std::string hysteria2, Proxy &node);
void explodeVless(std::string vless, Proxy &node);
void explodeTUIC(std::string TUIC, Proxy &node);
void explodeMierus(std::string mieru, Proxy &node);
void explodeQuan(const std::string &quan, Proxy &node);
void explodeStdVMess(std::string vmess, Proxy &node);
void explodeShadowrocket(std::string kit, Proxy &node);
void explodeKitsunebi(std::string kit, Proxy &node);
void explodeStdHysteria(std::string hysteria, Proxy &node);
void explodeStdHysteria2(std::string hysteria2, Proxy &node);
void explodeStdVless(std::string vless, Proxy &node);
void explodeStdTUIC(std::string TUIC, Proxy &node);
void explodeStdMieru(std::string mieru, Proxy &node);

/// Parse a link
void explode(const std::string &link, Proxy &node);
void explodeSSD(std::string link, std::vector<Proxy> &nodes);
void explodeSub(std::string sub, std::vector<Proxy> &nodes);
int explodeConf(const std::string &filepath, std::vector<Proxy> &nodes);
int explodeConfContent(const std::string &content, std::vector<Proxy> &nodes);

#endif // SUBPARSER_H_INCLUDED
