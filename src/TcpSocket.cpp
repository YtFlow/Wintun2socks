#include "pch.h"
#include "TcpSocket.h"
#include "TcpSocket.g.cpp"

namespace winrt::Wintun2socks::implementation
{
    winrt::event<EstablishedTcpHandler> TcpSocket::m_establishedTcp;
    std::unordered_map<uint16_t, winrt::com_ptr<winrt::Wintun2socks::implementation::TcpSocket>> TcpSocket::m_socketmap;
	err_t TcpSocket::tcp_recv_func(void* arg, tcp_pcb* tpcb, pbuf* p, err_t err)
	{
        winrt::com_ptr<TcpSocket> socket{ nullptr };
        std::vector<uint8_t> arr;
        auto it = TcpSocket::m_socketmap.find(tpcb->remote_port);
        if (it == TcpSocket::m_socketmap.end()) {
            goto ERR_ABORT;
        }
        socket = it->second;
        if (socket == nullptr) {
            goto ERR_ABORT;
        }
        if (p == NULL) {
            socket->m_recvFinished(*socket);
            return ERR_OK;
        }
        // TODO: wrap pbuf with a IBuffer
        arr.resize(p->tot_len);
        pbuf_copy_partial(p, arr.data(), p->tot_len, 0);
        socket->m_dataReceived(*socket, arr);
        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
        return ERR_OK;

	ERR_ABORT:
        if (p != NULL) {
            pbuf_free(p);
        }
        tcp_abort(tpcb);
        return ERR_ABRT;
	}
	err_t TcpSocket::tcp_sent_func(void* arg, tcp_pcb* tpcb, uint16_t len)
	{
        winrt::com_ptr<TcpSocket> socket{ nullptr };
        auto it = TcpSocket::m_socketmap.find(tpcb->remote_port);
        if (it == TcpSocket::m_socketmap.end()) {
            goto ERR_ABORT;
        }
        socket = it->second;
        if (socket == nullptr) {
            goto ERR_ABORT;
        }
        socket->m_dataSent(*socket, len, tcp_sndbuf(tpcb));
        return ERR_OK;
	ERR_ABORT:
        tcp_abort(tpcb);
        return ERR_ABRT;
	}
    err_t TcpSocket::tcp_err_func(void* arg, err_t err)
    {
        if (arg == NULL) return ERR_OK;
        winrt::com_ptr<TcpSocket> socket{ nullptr };
        auto it = TcpSocket::m_socketmap.find((u16_t)arg);
        if (it == TcpSocket::m_socketmap.end()) {
            return ERR_OK;
        }
        socket = it->second;
        if (socket == nullptr) {
            return ERR_OK;
        }
        socket->m_released = true;
        socket->m_socketError(*socket, err);
        m_socketmap.erase(it->first);
        return ERR_OK;
    }
    TcpSocket::TcpSocket(tcp_pcb* pcb)
    {
        m_tcpb = pcb;
        tcp_recv(pcb, (tcp_recv_fn)&tcp_recv_func);
        tcp_sent(pcb, (tcp_sent_fn)&tcp_sent_func);
        tcp_err(pcb, (tcp_err_fn)&tcp_err_func);
        tcp_arg(pcb, (void*)pcb->remote_port);
        tcp_nagle_disable(pcb);

        TcpSocket::m_socketmap.insert_or_assign(pcb->remote_port, this->get_strong());
    }
    uint8_t TcpSocket::Send(uint8_t* packet, uint16_t len, bool more)
    {
        if (m_released) {
            return ERR_RST;
        }
        auto flag = TCP_WRITE_FLAG_COPY;
        if (more) {
            flag |= TCP_WRITE_FLAG_MORE;
        }
        auto ret = tcp_write(m_tcpb, packet, len, flag);
        if (ret == ERR_OK) {
            return tcp_output(m_tcpb);
        }
        else return ret;
    }
	winrt::event_token TcpSocket::EstablishedTcp(Wintun2socks::EstablishedTcpHandler const& handler)
    {
        return m_establishedTcp.add(handler);
    }
    void TcpSocket::EstablishedTcp(winrt::event_token const& token) noexcept
    {
        m_establishedTcp.remove(token);
    }
    uint32_t TcpSocket::ConnectionCount() noexcept
    {
        return (uint32_t)m_socketmap.size();
    }
    void TcpSocket::Deinit() noexcept
    {
        m_socketmap.clear();
    }
    uint32_t TcpSocket::RemoteAddr()
    {
        return m_tcpb->local_ip.addr;
    }
    uint16_t TcpSocket::RemotePort()
    {
        return m_tcpb->local_port;
    }
    uint16_t TcpSocket::SendBufferSize()
    {
        return tcp_sndbuf(m_tcpb);
    }
    uint8_t TcpSocket::Send(uint64_t packet, uint16_t len, bool more)
    {
        return Send((uint8_t*)packet, len, more);
    }
    void TcpSocket::Recved(uint16_t len)
    {
        if (m_released) return;
        tcp_recved(m_tcpb, len);
    }
    uint8_t TcpSocket::Output()
    {
        if (m_released) return ERR_RST;
        return tcp_output(m_tcpb);
    }
    uint8_t TcpSocket::Shutdown()
    {
        if (m_released) return -1;
        m_released = true;
        TcpSocket::m_socketmap.erase(m_tcpb->remote_port);
        tcp_arg(m_tcpb, NULL);
        tcp_recv(m_tcpb, NULL);
        tcp_sent(m_tcpb, NULL);
        tcp_err(m_tcpb, NULL);
        if (m_tcpb->local_port == 0) {
            // Already closed
            // ret = tcp_close(m_tcpb);
            // tcp_abort(m_tcpb);
            return ERR_OK;
        }
        else {
            return tcp_close(m_tcpb);
        }
    }
    void TcpSocket::Abort()
    {
        if (m_released) return;
        m_released = true;
        TcpSocket::m_socketmap.erase(m_tcpb->remote_port);
        tcp_arg(m_tcpb, NULL);
        tcp_recv(m_tcpb, NULL);
        tcp_sent(m_tcpb, NULL);
        tcp_err(m_tcpb, NULL);
        tcp_abort(m_tcpb);
    }
    winrt::event_token TcpSocket::DataReceived(Wintun2socks::DataReceivedHandler const& handler)
    {
        return m_dataReceived.add(handler);
    }
    void TcpSocket::DataReceived(winrt::event_token const& token) noexcept
    {
        m_dataReceived.remove(token);
    }
    winrt::event_token TcpSocket::DataSent(Wintun2socks::DataSentHandler const& handler)
    {
        return m_dataSent.add(handler);
    }
    void TcpSocket::DataSent(winrt::event_token const& token) noexcept
    {
        m_dataSent.remove(token);
    }
    winrt::event_token TcpSocket::SocketError(Wintun2socks::SocketErrorHandler const& handler)
    {
        return m_socketError.add(handler);
    }
    void TcpSocket::SocketError(winrt::event_token const& token) noexcept
    {
        m_socketError.remove(token);
    }
    winrt::event_token TcpSocket::RecvFinished(Wintun2socks::RecvFinishedHandler const& handler)
    {
        return m_recvFinished.add(handler);
    }
    void TcpSocket::RecvFinished(winrt::event_token const& token) noexcept
    {
        m_recvFinished.remove(token);
    }
    TcpSocket::~TcpSocket()
    {
        Abort();
    }
}
