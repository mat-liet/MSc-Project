package com.fakesnort.packetsniffer.amqp.producer;

import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DETECTION_ROUTING_KEY;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.EXCHANGE;

import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

@Service
public class DetectionProducer {
	
    private static final Logger LOGGER = LoggerFactory.getLogger(DetectionProducer.class);
    
    private RabbitTemplate rabbitTemplate;
    
    public DetectionProducer(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    public void sendMessage(Packet message){
        LOGGER.info(String.format("Packet sent to detection queue"));
        rabbitTemplate.convertAndSend(EXCHANGE, DETECTION_ROUTING_KEY, message);
    }

}
