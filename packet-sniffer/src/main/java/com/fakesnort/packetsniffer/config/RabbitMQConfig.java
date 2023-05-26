package com.fakesnort.packetsniffer.config;

import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DATABASE_Q_NAME;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DATABASE_ROUTING_KEY;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DETECTION_Q_NAME;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.DETECTION_ROUTING_KEY;
import static com.fakesnort.packetsniffer.config.PacketSnifferRoutingConstants.EXCHANGE;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {

    // spring bean for rabbitmq queue
    @Bean
    public Queue detectionQueue(){
        return new Queue(DETECTION_Q_NAME);
    }
    
    @Bean
    public Queue databaseQueue(){
        return new Queue(DATABASE_Q_NAME);
    }

    // binding between queue and exchange using routing key
    @Bean
    public Binding detectionQBinding(){
        return BindingBuilder
                .bind(detectionQueue())
                .to(exchange())
                .with(DETECTION_ROUTING_KEY);
    }
    
    @Bean
    public Binding databaseQBinding(){
        return BindingBuilder
                .bind(databaseQueue())
                .to(exchange())
                .with(DATABASE_ROUTING_KEY);
    }
    
    // spring bean for rabbitmq exchange
    @Bean
    public TopicExchange exchange(){
        return new TopicExchange(EXCHANGE);
    }

// Spring boot autoconfiguration provides following beans
    // ConnectionFactory
    // RabbitTemplate
    // RabbitAdmin
}