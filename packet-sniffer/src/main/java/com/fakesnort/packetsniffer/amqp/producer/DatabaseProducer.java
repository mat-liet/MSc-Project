package com.fakesnort.packetsniffer.amqp.producer;

import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DATABASE_ROUTING_KEY;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.EXCHANGE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;

@Service
public class DatabaseProducer {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseProducer.class);
    
    private RabbitTemplate rabbitTemplate;
    
    public DatabaseProducer(RabbitTemplate rabbitTemplate) {
        this.rabbitTemplate = rabbitTemplate;
    }

    public void sendMessage(CapturedPacket message){
        LOGGER.info(String.format("Packet sent to database queue"));
        rabbitTemplate.convertAndSend(EXCHANGE, DATABASE_ROUTING_KEY, message);
    }

}
