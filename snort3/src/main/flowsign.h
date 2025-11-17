//--------------------------------------------------------------------------
// FlowSign lightweight scaffolding
// Provides a background thread for handling deep-copied packet snapshots and
// computing simple sliding-window flow feature vectors inspired by
// CICFlowMeter.
//--------------------------------------------------------------------------

#ifndef MAIN_FLOWSIGN_H
#define MAIN_FLOWSIGN_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "sfip/sf_ip.h"

struct timeval;

namespace snort
{
struct Packet;
namespace ip
{
class IpApi;
}
class SfIp;

// Simple representation of an abstracted packet snapshot that FlowSign can
// safely use off the Snort hot path.
struct FlowSignSample
{
    timeval ts{};
    uint32_t packet_flags = 0;
    uint32_t proto_bits = 0;
    uint32_t pktlen = 0;
    uint16_t sp = 0;
    uint16_t dp = 0;
    uint8_t ip_proto = 0;
    uint8_t tcp_flags = 0;
    uint8_t ip_header_len = 0;
    uint8_t transport_header_len = 0;
    uint16_t payload_len = 0;
    ip::IpApi ip_api{};
    std::vector<uint8_t> bytes;
};

struct FlowKey
{
    SfIp* src = nullptr;
    SfIp* dst = nullptr;
    uint16_t sp = 0;
    uint16_t dp = 0;
    uint8_t proto = 0;
};

struct FlowKeyStorage
{
    FlowKeyStorage() = default;
    FlowKeyStorage(const FlowKeyStorage&) = default;
    FlowKeyStorage& operator=(const FlowKeyStorage&) = default;

    FlowKeyStorage(const FlowKey& key);

    bool operator==(const FlowKeyStorage& other) const;

    SfIp src{};
    SfIp dst{};
    uint16_t sp = 0;
    uint16_t dp = 0;
    uint8_t proto = 0;
};

struct FlowKeyHash
{
    size_t operator()(const FlowKeyStorage& key) const;
};

// Sliding-window flow metrics derived from a fixed-size circular buffer.
struct FlowFeatureVector
{
    uint64_t flow_duration_us = 0;
    uint32_t total_fwd_packets = 0;
    uint32_t total_bwd_packets = 0;
    uint64_t total_length_fwd = 0;
    uint64_t total_length_bwd = 0;
    double fwd_pkt_len_min = 0.0;
    double fwd_pkt_len_max = 0.0;
    double fwd_pkt_len_mean = 0.0;
    double fwd_pkt_len_std = 0.0;
    double bwd_pkt_len_min = 0.0;
    double bwd_pkt_len_max = 0.0;
    double bwd_pkt_len_mean = 0.0;
    double bwd_pkt_len_std = 0.0;
    double flow_bytes_per_s = 0.0;
    double flow_packets_per_s = 0.0;
    double flow_iat_mean = 0.0;
    double flow_iat_std = 0.0;
    double flow_iat_max = 0.0;
    double flow_iat_min = 0.0;
    double fwd_iat_min = 0.0;
    double fwd_iat_max = 0.0;
    double fwd_iat_mean = 0.0;
    double fwd_iat_std = 0.0;
    double fwd_iat_total = 0.0;
    double bwd_iat_min = 0.0;
    double bwd_iat_max = 0.0;
    double bwd_iat_mean = 0.0;
    double bwd_iat_std = 0.0;
    double bwd_iat_total = 0.0;
    uint32_t fwd_psh_flags = 0;
    uint32_t bwd_psh_flags = 0;
    uint32_t fwd_urg_flags = 0;
    uint32_t bwd_urg_flags = 0;
    uint64_t fwd_header_length = 0;
    uint64_t bwd_header_length = 0;
    double fwd_packets_per_s = 0.0;
    double bwd_packets_per_s = 0.0;
    double packet_len_min = 0.0;
    double packet_len_max = 0.0;
    double packet_len_mean = 0.0;
    double packet_len_std = 0.0;
    double packet_len_var = 0.0;
    uint32_t fin_flag_count = 0;
    uint32_t syn_flag_count = 0;
    uint32_t rst_flag_count = 0;
    uint32_t psh_flag_count = 0;
    uint32_t ack_flag_count = 0;
    uint32_t urg_flag_count = 0;
    uint32_t cwr_flag_count = 0;
    uint32_t ece_flag_count = 0;
    double down_up_ratio = 0.0;
    double average_packet_size = 0.0;
    double fwd_segment_size_avg = 0.0;
    double bwd_segment_size_avg = 0.0;
    double fwd_bytes_bulk_avg = 0.0;
    double fwd_packet_bulk_avg = 0.0;
    double fwd_bulk_rate_avg = 0.0;
    double bwd_bytes_bulk_avg = 0.0;
    double bwd_packet_bulk_avg = 0.0;
    double bwd_bulk_rate_avg = 0.0;
    double subflow_fwd_packets = 0.0;
    double subflow_fwd_bytes = 0.0;
    double subflow_bwd_packets = 0.0;
    double subflow_bwd_bytes = 0.0;
    uint32_t fwd_init_win_bytes = 0;
    uint32_t bwd_init_win_bytes = 0;
    uint32_t fwd_act_data_pkts = 0;
    uint32_t fwd_seg_size_min = 0;
    double active_min = 0.0;
    double active_mean = 0.0;
    double active_max = 0.0;
    double active_std = 0.0;
    double idle_min = 0.0;
    double idle_mean = 0.0;
    double idle_max = 0.0;
    double idle_std = 0.0;
};

class FlowSignManager
{
public:
    static FlowSignManager& get_instance();

    void start();
    void shutdown();

    void enqueue_packet(const Packet& packet);

private:
    FlowSignManager() = default;
    FlowSignManager(const FlowSignManager&) = delete;
    FlowSignManager& operator=(const FlowSignManager&) = delete;

    void worker_loop();
    FlowFeatureVector recompute_features(const FlowKeyStorage& key, const std::deque<FlowSignSample>& window_copy);
    static void evaluate_features(const FlowKeyStorage& key, const FlowFeatureVector& features);

private:
    static constexpr size_t window_size = 50;

    std::atomic<bool> running{false};
    std::thread worker;

    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    std::deque<FlowSignSample> work_queue;
    std::unordered_map<FlowKeyStorage, std::deque<FlowSignSample>, FlowKeyHash> sliding_windows;
};
}

#endif

