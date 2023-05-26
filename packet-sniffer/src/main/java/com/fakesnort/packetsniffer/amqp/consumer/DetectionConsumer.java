package com.fakesnort.packetsniffer.amqp.consumer;

import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DETECTION_Q_NAME;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.service.DetectionService;

@Service
public class DetectionConsumer {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(DetectionConsumer.class);
	
	@Autowired
	private DetectionService detectionService;
	
	@RabbitListener(queues = {DETECTION_Q_NAME})
    public void consume(Packet packet){
        LOGGER.info(String.format("Packet received in detection consumer"));
        detectionService.handlePacket(packet);
    }

}
