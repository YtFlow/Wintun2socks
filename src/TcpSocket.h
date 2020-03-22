#pragma once
#include "TcpSocket.g.h"
#include "lwip\err.h"
#include "lwip\tcp.h"

namespace winrt::Wintun2socks::implementation
{
    struct TcpSocket : TcpSocketT<TcpSocket>
    {
    private:
        static std::unordered_map<uint16_t, winrt::com_ptr<winrt::Wintun2socks::implementation::TcpSocket>> m_socketmap;
        static err_t tcp_recv_func(void* arg, tcp_pcb *tpcb, pbuf *p, err_t err);
        static err_t tcp_sent_func(void* arg, tcp_pcb *tpcb, uint16_t len);
        static err_t tcp_err_func(void* arg, err_t err);
        tcp_pcb* m_tcpb;
        bool m_released = false;
        uint8_t Send(uint8_t* packet, uint16_t len, bool more);
        winrt::event<DataReceivedHandler> m_dataReceived;
        winrt::event<DataSentHandler> m_dataSent;
        winrt::event<SocketErrorHandler> m_socketError;
        winrt::event<RecvFinishedHandler> m_recvFinished;
    public:
        TcpSocket(tcp_pcb* pcb);

        static winrt::event<EstablishedTcpHandler> m_establishedTcp;
        static winrt::event_token EstablishedTcp(Wintun2socks::EstablishedTcpHandler const& handler);
        static void EstablishedTcp(winrt::event_token const& token) noexcept;
        static uint32_t ConnectionCount() noexcept;
        static void Deinit() noexcept;
        uint32_t RemoteAddr();
        uint16_t RemotePort();
        uint16_t SendBufferSize();
        uint8_t Send(uint64_t packet, uint16_t len, bool more);
        void Recved(uint16_t len);
        uint8_t Output();
        uint8_t Shutdown();
        void Abort();
        winrt::event_token DataReceived(Wintun2socks::DataReceivedHandler const& handler);
        void DataReceived(winrt::event_token const& token) noexcept;
        winrt::event_token DataSent(Wintun2socks::DataSentHandler const& handler);
        void DataSent(winrt::event_token const& token) noexcept;
        winrt::event_token SocketError(Wintun2socks::SocketErrorHandler const& handler);
        void SocketError(winrt::event_token const& token) noexcept;
        winrt::event_token RecvFinished(Wintun2socks::RecvFinishedHandler const& handler);
        void RecvFinished(winrt::event_token const& token) noexcept;

        virtual ~TcpSocket();
    };
}
namespace winrt::Wintun2socks::factory_implementation
{
    struct TcpSocket : TcpSocketT<TcpSocket, implementation::TcpSocket>
    {
    };
}
