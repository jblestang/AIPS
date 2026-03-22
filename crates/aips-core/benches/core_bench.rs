use criterion::{black_box, criterion_group, criterion_main, Criterion};
use aips_core::layer::PacketView;
use aips_core::classifier::Classifier;
use aips_core::qos::QosFields;

fn bench_packet_view(c: &mut Criterion) {
    // A synthetic Ethernet / IPv4 / TCP payload
    // ETH: 14 bytes (header)
    // IPv4: 20 bytes (header) + src_ip(4), dst_ip(4)
    // TCP: 20 bytes (header) + src_port(2), dst_port(2)
    // Payload: 4 bytes: "AIPS"
    let pkt_data: &[u8] = &[
        // Ethernet Header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4 Header (version 4, IHL 5 = 20 bytes, DSCP=0, Total Len=44, ID=0, Flags/Frag=0, TTL=64, Proto=6 (TCP), Csum, Src=1.2.3.4, Dst=5.6.7.8)
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        // TCP Header (SrcPort=1234, DstPort=80, Seq=0, Ack=0, DataOff=5 (20 bytes), Flags=0x18 (PSH, ACK), Window=1000, Csum, Urg=0)
        0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00,
        // Payload
        0x41, 0x49, 0x50, 0x53
    ];

    c.bench_function("PacketView::parse", |b| {
        b.iter(|| {
            let view = PacketView::parse(black_box(pkt_data));
            black_box(view)
        })
    });

    let mut classifier: Classifier<128> = Classifier::new();
    let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
    
    c.bench_function("Classifier::classify", |b| {
        b.iter(|| {
            // Need to parse first to get the struct
            if let Some(view) = PacketView::parse(black_box(pkt_data)) {
                let decision = classifier.classify(&view, qos);
                black_box(decision);
            }
        })
    });
}

criterion_group!(benches, bench_packet_view);
criterion_main!(benches);
