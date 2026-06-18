use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use rust_xhttp::vless::Address;
use rust_xhttp::xudp::{
    Frame, OPTION_DATA, STATUS_NEW, Target, encode_frame, encode_plain_datagram,
};
use std::net::Ipv4Addr;

fn bench_xudp_frame_encode(c: &mut Criterion) {
    let frame = Frame {
        session_id: 7,
        status: STATUS_NEW,
        option: OPTION_DATA,
        target: Some(Target {
            address: Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 53,
        }),
        global_id: Some([9; 8]),
        payload: Bytes::from(vec![0u8; 1200]),
    };

    c.bench_function("xudp frame encode 1200b", |b| {
        b.iter(|| encode_frame(&frame).unwrap())
    });
}

fn bench_plain_datagram_encode(c: &mut Criterion) {
    let payload = [0u8; 1200];
    c.bench_function("plain udp datagram encode 1200b", |b| {
        b.iter(|| encode_plain_datagram(&payload).unwrap())
    });
}

criterion_group!(
    benches,
    bench_xudp_frame_encode,
    bench_plain_datagram_encode
);
criterion_main!(benches);
