//--------------------------------------------------------------------------
//--------------------------------------------------------------------------
// FlowSign lightweight scaffolding with CICFlowMeter-inspired features
//--------------------------------------------------------------------------
//--------------------------------------------------------------------------

#include "flowsign.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <numeric>
#include <unordered_map>

#include "log/log.h"
#include "protocols/ip.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "sfip/sf_ip.h"

using namespace std::chrono;

namespace snort
{
namespace
{
struct Stats
{
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double stddev = 0.0;
    double variance = 0.0;
};

Stats compute_stats(const std::vector<double>& values)
{
    Stats stats;
    if (values.empty())
        return stats;

    stats.min = *std::min_element(values.begin(), values.end());
    stats.max = *std::max_element(values.begin(), values.end());
    stats.mean = std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());

    double accum = 0.0;
    for (double v : values)
        accum += (v - stats.mean) * (v - stats.mean);
    stats.variance = accum / static_cast<double>(values.size());
    stats.stddev = std::sqrt(stats.variance);
    return stats;
}

FlowKeyStorage::FlowKeyStorage(const FlowKey& key)
{
    if (key.src)
        src = *key.src;
    if (key.dst)
        dst = *key.dst;
    sp = key.sp;
    dp = key.dp;
    proto = key.proto;
}

bool FlowKeyStorage::operator==(const FlowKeyStorage& other) const
{
    return proto == other.proto && sp == other.sp && dp == other.dp && src == other.src && dst == other.dst;
}

static size_t hash_ip(const SfIp& ip)
{
    const uint32_t* words = ip.get_ptr();
    size_t h = std::hash<int>{}(ip.get_family());
    for (int i = 0; i < 4; ++i)
    {
        h ^= std::hash<uint32_t>{}(words[i] + 0x9e3779b9 + (h << 6) + (h >> 2));
    }
    return h;
}

size_t FlowKeyHash::operator()(const FlowKeyStorage& key) const
{
    size_t h = hash_ip(key.src);
    h ^= hash_ip(key.dst) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(key.sp) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(key.dp) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint8_t>{}(key.proto) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

FlowSignSample copy_packet(const Packet& packet)
{
    FlowSignSample sample;

    if (packet.pkth)
        sample.ts = packet.pkth->ts;

    sample.packet_flags = packet.packet_flags;
    sample.proto_bits = packet.proto_bits;
    sample.pktlen = packet.pktlen;
    sample.sp = packet.ptrs.sp;
    sample.dp = packet.ptrs.dp;
    sample.ip_proto = static_cast<uint8_t>(packet.ptrs.ip_api.proto());
    sample.tcp_flags = packet.ptrs.tcph ? packet.ptrs.tcph->th_flags : 0;
    sample.ip_header_len = packet.ptrs.ip_api.hlen();
    sample.transport_header_len = packet.ptrs.tcph ? packet.ptrs.tcph->hlen()
        : (packet.ptrs.udph ? sizeof(udp::UDPHdr) : 0);
    sample.payload_len = packet.ptrs.ip_api.pay_len();
    sample.ip_api = packet.ptrs.ip_api;

    if (packet.pkt && packet.pktlen)
    {
        sample.bytes.resize(packet.pktlen);
        memcpy(sample.bytes.data(), packet.pkt, packet.pktlen);
    }

    return sample;
}

FlowKey build_flow_key(const FlowSignSample& sample)
{
    FlowKey key;
    key.src = sample.ip_api.get_src();
    key.dst = sample.ip_api.get_dst();
    key.sp = sample.sp;
    key.dp = sample.dp;
    key.proto = sample.ip_proto;
    return key;
}

inline double seconds_between(const timeval& older, const timeval& newer)
{
    const auto start = seconds(older.tv_sec) + microseconds(older.tv_usec);
    const auto finish = seconds(newer.tv_sec) + microseconds(newer.tv_usec);
    return duration<double>(finish - start).count();
}

inline double micros_between(const timeval& older, const timeval& newer)
{
    return seconds_between(older, newer) * 1'000'000.0;
}
}

FlowSignManager& FlowSignManager::get_instance()
{
    static FlowSignManager instance;
    return instance;
}

void FlowSignManager::start()
{
    bool expected = false;
    if (running.compare_exchange_strong(expected, true))
        worker = std::thread(&FlowSignManager::worker_loop, this);
}

void FlowSignManager::shutdown()
{
    if (!running.exchange(false))
        return;

    queue_cv.notify_all();

    if (worker.joinable())
        worker.join();
}

void FlowSignManager::enqueue_packet(const Packet& packet)
{
    if (!running.load())
        return;

    FlowSignSample snapshot = copy_packet(packet);

    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        work_queue.push_back(std::move(snapshot));
    }

    queue_cv.notify_one();
}

void FlowSignManager::worker_loop()
{
    while (running.load())
    {
        FlowSignSample sample;
        FlowKeyStorage key;

        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [&] { return !work_queue.empty() || !running.load(); });

            if (!running.load() && work_queue.empty())
                break;

            sample = std::move(work_queue.front());
            work_queue.pop_front();
            key = FlowKeyStorage(build_flow_key(sample));
        }

        if (!key.src.is_set() || !key.dst.is_set())
            continue;

        std::deque<FlowSignSample> window_copy;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            auto& window = sliding_windows[key];
            window.push_back(std::move(sample));
            if (window.size() > window_size)
                window.pop_front();
            window_copy = window;
        }

        auto features = recompute_features(key, window_copy);
        evaluate_features(key, features);
    }
}

FlowFeatureVector FlowSignManager::recompute_features(const FlowKeyStorage& key, const std::deque<FlowSignSample>& window_copy)
{
    FlowFeatureVector features;

    if (window_copy.empty())
        return features;

    const SfIp* fwd_src = key.src.is_set() ? &key.src : nullptr;
    const SfIp* fwd_dst = key.dst.is_set() ? &key.dst : nullptr;
    const uint16_t fwd_sp = key.sp;
    const uint16_t fwd_dp = key.dp;

    std::vector<double> all_lengths;
    std::vector<double> fwd_lengths;
    std::vector<double> bwd_lengths;
    std::vector<double> all_iats;
    std::vector<double> fwd_iats;
    std::vector<double> bwd_iats;
    std::vector<double> active_periods;
    std::vector<double> idle_periods;

    uint32_t bulk_fwd_events = 0;
    uint32_t bulk_bwd_events = 0;
    double bulk_fwd_bytes = 0.0;
    double bulk_bwd_bytes = 0.0;
    double bulk_fwd_packets = 0.0;
    double bulk_bwd_packets = 0.0;

    const double idle_threshold_us = 1'000'000.0;

    timeval prev_ts = window_copy.front().ts;
    bool first_packet = true;
    bool first_fwd_seen = false;
    bool first_bwd_seen = false;
    timeval prev_fwd_ts{};
    timeval prev_bwd_ts{};

    uint64_t total_bytes = 0;

    uint32_t forward_segments = 0;
    uint32_t backward_segments = 0;

    uint32_t current_fwd_bulk_pkts = 0;
    uint32_t current_bwd_bulk_pkts = 0;
    double current_fwd_bulk_bytes = 0.0;
    double current_bwd_bulk_bytes = 0.0;
    timeval last_fwd_bulk_ts{};
    timeval last_bwd_bulk_ts{};

    for (const auto& sample : window_copy)
    {
        const bool is_forward = (fwd_src && fwd_dst && sample.ip_api.get_src() && sample.ip_api.get_dst()
            && *sample.ip_api.get_src() == *fwd_src && *sample.ip_api.get_dst() == *fwd_dst
            && sample.sp == fwd_sp && sample.dp == fwd_dp);
        const bool is_backward = (fwd_src && fwd_dst && sample.ip_api.get_src() && sample.ip_api.get_dst()
            && *sample.ip_api.get_src() == *fwd_dst && *sample.ip_api.get_dst() == *fwd_src
            && sample.sp == fwd_dp && sample.dp == fwd_sp);

        total_bytes += sample.pktlen;
        all_lengths.push_back(static_cast<double>(sample.pktlen));

        if (!first_packet)
            all_iats.push_back(micros_between(prev_ts, sample.ts));
        prev_ts = sample.ts;
        first_packet = false;

        if (is_forward)
        {
            features.total_fwd_packets++;
            features.total_length_fwd += sample.pktlen;
            fwd_lengths.push_back(static_cast<double>(sample.pktlen));
            features.fwd_header_length += sample.ip_header_len + sample.transport_header_len;
            forward_segments++;

            if (sample.tcp_flags & TH_PUSH)
                features.fwd_psh_flags++;
            if (sample.tcp_flags & TH_URG)
                features.fwd_urg_flags++;
            if (sample.tcp_flags & TH_ACK)
                features.fwd_act_data_pkts += (sample.payload_len > 0);
            if (sample.payload_len > 0)
            {
                if (features.fwd_seg_size_min == 0 || sample.payload_len < features.fwd_seg_size_min)
                    features.fwd_seg_size_min = sample.payload_len;
            }

            if (!first_fwd_seen)
            {
                prev_fwd_ts = sample.ts;
                first_fwd_seen = true;
            }
            else
            {
                double delta = micros_between(prev_fwd_ts, sample.ts);
                fwd_iats.push_back(delta);
                prev_fwd_ts = sample.ts;
            }

            double fwd_gap = first_fwd_seen ? micros_between(last_fwd_bulk_ts, sample.ts) : 0.0;
            if (!first_fwd_seen || fwd_gap > idle_threshold_us)
            {
                if (current_fwd_bulk_pkts > 0)
                {
                    bulk_fwd_events++;
                    bulk_fwd_bytes += current_fwd_bulk_bytes;
                    bulk_fwd_packets += current_fwd_bulk_pkts;
                }
                current_fwd_bulk_pkts = 0;
                current_fwd_bulk_bytes = 0.0;
            }
            current_fwd_bulk_pkts++;
            current_fwd_bulk_bytes += sample.pktlen;
            last_fwd_bulk_ts = sample.ts;
        }
        else if (is_backward)
        {
            features.total_bwd_packets++;
            features.total_length_bwd += sample.pktlen;
            bwd_lengths.push_back(static_cast<double>(sample.pktlen));
            features.bwd_header_length += sample.ip_header_len + sample.transport_header_len;
            backward_segments++;

            if (sample.tcp_flags & TH_PUSH)
                features.bwd_psh_flags++;
            if (sample.tcp_flags & TH_URG)
                features.bwd_urg_flags++;

            if (!first_bwd_seen)
            {
                prev_bwd_ts = sample.ts;
                first_bwd_seen = true;
            }
            else
            {
                double delta = micros_between(prev_bwd_ts, sample.ts);
                bwd_iats.push_back(delta);
                prev_bwd_ts = sample.ts;
            }

            double bwd_gap = first_bwd_seen ? micros_between(last_bwd_bulk_ts, sample.ts) : 0.0;
            if (!first_bwd_seen || bwd_gap > idle_threshold_us)
            {
                if (current_bwd_bulk_pkts > 0)
                {
                    bulk_bwd_events++;
                    bulk_bwd_bytes += current_bwd_bulk_bytes;
                    bulk_bwd_packets += current_bwd_bulk_pkts;
                }
                current_bwd_bulk_pkts = 0;
                current_bwd_bulk_bytes = 0.0;
            }
            current_bwd_bulk_pkts++;
            current_bwd_bulk_bytes += sample.pktlen;
            last_bwd_bulk_ts = sample.ts;
        }

        if (sample.tcp_flags & TH_FIN) features.fin_flag_count++;
        if (sample.tcp_flags & TH_SYN) features.syn_flag_count++;
        if (sample.tcp_flags & TH_RST) features.rst_flag_count++;
        if (sample.tcp_flags & TH_PUSH) features.psh_flag_count++;
        if (sample.tcp_flags & TH_ACK) features.ack_flag_count++;
        if (sample.tcp_flags & TH_URG) features.urg_flag_count++;
        if (sample.tcp_flags & TH_CWR) features.cwr_flag_count++;
        if (sample.tcp_flags & TH_ECE) features.ece_flag_count++;
    }

    // finalize bulks
    if (current_fwd_bulk_pkts > 0)
    {
        bulk_fwd_events++;
        bulk_fwd_bytes += current_fwd_bulk_bytes;
        bulk_fwd_packets += current_fwd_bulk_pkts;
    }
    if (current_bwd_bulk_pkts > 0)
    {
        bulk_bwd_events++;
        bulk_bwd_bytes += current_bwd_bulk_bytes;
        bulk_bwd_packets += current_bwd_bulk_pkts;
    }

    const timeval& oldest = window_copy.front().ts;
    const timeval& newest = window_copy.back().ts;
    const double duration_us = std::max(micros_between(oldest, newest), 1.0);
    features.flow_duration_us = static_cast<uint64_t>(duration_us);

    Stats all_len_stats = compute_stats(all_lengths);
    features.packet_len_min = all_len_stats.min;
    features.packet_len_max = all_len_stats.max;
    features.packet_len_mean = all_len_stats.mean;
    features.packet_len_std = all_len_stats.stddev;
    features.packet_len_var = all_len_stats.variance;
    features.average_packet_size = all_len_stats.mean;

    Stats fwd_len_stats = compute_stats(fwd_lengths);
    features.fwd_pkt_len_min = fwd_len_stats.min;
    features.fwd_pkt_len_max = fwd_len_stats.max;
    features.fwd_pkt_len_mean = fwd_len_stats.mean;
    features.fwd_pkt_len_std = fwd_len_stats.stddev;
    features.fwd_segment_size_avg = fwd_len_stats.mean;

    Stats bwd_len_stats = compute_stats(bwd_lengths);
    features.bwd_pkt_len_min = bwd_len_stats.min;
    features.bwd_pkt_len_max = bwd_len_stats.max;
    features.bwd_pkt_len_mean = bwd_len_stats.mean;
    features.bwd_pkt_len_std = bwd_len_stats.stddev;
    features.bwd_segment_size_avg = bwd_len_stats.mean;

    Stats iat_stats = compute_stats(all_iats);
    features.flow_iat_mean = iat_stats.mean;
    features.flow_iat_std = iat_stats.stddev;
    features.flow_iat_max = iat_stats.max;
    features.flow_iat_min = iat_stats.min;

    Stats fwd_iat_stats = compute_stats(fwd_iats);
    features.fwd_iat_min = fwd_iat_stats.min;
    features.fwd_iat_max = fwd_iat_stats.max;
    features.fwd_iat_mean = fwd_iat_stats.mean;
    features.fwd_iat_std = fwd_iat_stats.stddev;
    features.fwd_iat_total = std::accumulate(fwd_iats.begin(), fwd_iats.end(), 0.0);

    Stats bwd_iat_stats = compute_stats(bwd_iats);
    features.bwd_iat_min = bwd_iat_stats.min;
    features.bwd_iat_max = bwd_iat_stats.max;
    features.bwd_iat_mean = bwd_iat_stats.mean;
    features.bwd_iat_std = bwd_iat_stats.stddev;
    features.bwd_iat_total = std::accumulate(bwd_iats.begin(), bwd_iats.end(), 0.0);

    features.flow_bytes_per_s = (static_cast<double>(total_bytes) / duration_us) * 1'000'000.0;
    const double packet_count = static_cast<double>(window_copy.size());
    features.flow_packets_per_s = (packet_count / duration_us) * 1'000'000.0;
    features.fwd_packets_per_s = (features.total_fwd_packets / duration_us) * 1'000'000.0;
    features.bwd_packets_per_s = (features.total_bwd_packets / duration_us) * 1'000'000.0;

    features.down_up_ratio = (features.total_fwd_packets > 0)
        ? static_cast<double>(features.total_bwd_packets) / static_cast<double>(features.total_fwd_packets)
        : 0.0;

    features.fwd_bytes_bulk_avg = bulk_fwd_events ? (bulk_fwd_bytes / static_cast<double>(bulk_fwd_events)) : 0.0;
    features.fwd_packet_bulk_avg = bulk_fwd_events ? (bulk_fwd_packets / static_cast<double>(bulk_fwd_events)) : 0.0;
    features.fwd_bulk_rate_avg = (bulk_fwd_events && duration_us > 0.0)
        ? (bulk_fwd_bytes / duration_us) * 1'000'000.0 : 0.0;

    features.bwd_bytes_bulk_avg = bulk_bwd_events ? (bulk_bwd_bytes / static_cast<double>(bulk_bwd_events)) : 0.0;
    features.bwd_packet_bulk_avg = bulk_bwd_events ? (bulk_bwd_packets / static_cast<double>(bulk_bwd_events)) : 0.0;
    features.bwd_bulk_rate_avg = (bulk_bwd_events && duration_us > 0.0)
        ? (bulk_bwd_bytes / duration_us) * 1'000'000.0 : 0.0;

    features.subflow_fwd_packets = forward_segments;
    features.subflow_fwd_bytes = features.total_length_fwd;
    features.subflow_bwd_packets = backward_segments;
    features.subflow_bwd_bytes = features.total_length_bwd;

    // Active/idle calculation
    first_packet = true;
    timeval active_start{};
    for (const auto& sample : window_copy)
    {
        if (first_packet)
        {
            active_start = sample.ts;
            prev_ts = sample.ts;
            first_packet = false;
            continue;
        }

        double gap = micros_between(prev_ts, sample.ts);
        if (gap > idle_threshold_us)
        {
            active_periods.push_back(micros_between(active_start, prev_ts));
            idle_periods.push_back(gap);
            active_start = sample.ts;
        }
        prev_ts = sample.ts;
    }

    if (!first_packet)
        active_periods.push_back(micros_between(active_start, prev_ts));

    Stats active_stats = compute_stats(active_periods);
    features.active_min = active_stats.min;
    features.active_mean = active_stats.mean;
    features.active_max = active_stats.max;
    features.active_std = active_stats.stddev;

    Stats idle_stats = compute_stats(idle_periods);
    features.idle_min = idle_stats.min;
    features.idle_mean = idle_stats.mean;
    features.idle_max = idle_stats.max;
    features.idle_std = idle_stats.stddev;

    return features;
}

void FlowSignManager::evaluate_features(const FlowKeyStorage& key, const FlowFeatureVector& features)
{
    SfIpString src_buf{};
    SfIpString dst_buf{};
    key.src.ntop(src_buf);
    key.dst.ntop(dst_buf);

    LogMessage(
        "[FlowSign] %s:%u -> %s:%u proto=%u flow_dur=%.0fus fwd_pkts=%u bwd_pkts=%u bytes/s=%.2f pkts/s=%.2f fwd_mean_len=%.2f bwd_mean_len=%.2f\n",
        src_buf,
        key.sp,
        dst_buf,
        key.dp,
        key.proto,
        static_cast<double>(features.flow_duration_us),
        features.total_fwd_packets,
        features.total_bwd_packets,
        features.flow_bytes_per_s,
        features.flow_packets_per_s,
        features.fwd_pkt_len_mean,
        features.bwd_pkt_len_mean);
}
}

