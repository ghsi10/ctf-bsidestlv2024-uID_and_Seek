FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y qemu-system-x86 qemu-utils socat && \
    rm -rf /var/lib/apt/lists/*

COPY bzImage initramfs.cpio.gz qemu-cmd.sh run.sh /challenge/

WORKDIR /challenge

RUN chmod +x *.sh

EXPOSE 4444

CMD ["./run.sh"]