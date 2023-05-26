package com.fakesnort.packetsniffer.amqp.consumer;

import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DATABASE_Q_NAME;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;
import com.fakesnort.packetsniffer.service.DatabaseService;

@Service
public class DatabaseConsumer {
	
private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseConsumer.class);
	
	@Autowired
	private DatabaseService databaseService;
	
	@RabbitListener(queues = {DATABASE_Q_NAME})
    public void consume(CapturedPacket packet){
        LOGGER.info(String.format("Packet received in database consumer"));
//        databaseService.handlePacket(packet);
    }

}
