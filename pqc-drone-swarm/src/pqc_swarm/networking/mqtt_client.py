"""MQTT Network transport layer for PQC Drone Swarm coordination."""

import json
import logging
from typing import Callable, Dict, Any, Optional

import paho.mqtt.client as mqtt

logger = logging.getLogger("pqc_mqtt")

# Standard Swarm Topics
TOPIC_COMMANDS = "swarm/commands"
TOPIC_APPROVALS = "swarm/approvals"
TOPIC_SHARES = "swarm/shares"
TOPIC_REGISTRY = "swarm/registry"
TOPIC_TELEMETRY = "swarm/telemetry"


class SwarmMQTTTransport:
    """
    Manages asynchronous MQTT pub/sub connectivity over the simulated wireless mesh channel.
    """

    def __init__(
        self,
        client_id: str,
        broker_host: str = "localhost",
        broker_port: int = 1883,
        keepalive: int = 60,
    ):
        self.client_id = client_id
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.keepalive = keepalive

        # Use CallbackAPIVersion.VERSION2 for paho-mqtt 2.x compatibility
        try:
            self.client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
            )
        except AttributeError:
            # Fallback for older paho-mqtt 1.x
            self.client = mqtt.Client(client_id=self.client_id)

        self._callbacks: Dict[str, Callable[[str, Dict[str, Any]], None]] = {}

        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        self.is_connected = False

    def register_handler(self, topic: str, handler: Callable[[str, Dict[str, Any]], None]) -> None:
        """Register a callback for incoming messages on a topic."""
        self._callbacks[topic] = handler

    def connect(self, max_retries: int = 10, retry_delay: float = 1.5) -> None:
        """Connect to the MQTT broker with retry logic and start background network loop."""
        import time
        logger.info(f"[{self.client_id}] Connecting to MQTT broker at {self.broker_host}:{self.broker_port}...")
        for attempt in range(1, max_retries + 1):
            try:
                self.client.connect(self.broker_host, self.broker_port, self.keepalive)
                self.client.loop_start()
                return
            except Exception as e:
                logger.warning(f"[{self.client_id}] Broker connection attempt {attempt}/{max_retries} failed ({e}). Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
        raise ConnectionError(f"[{self.client_id}] Failed to connect to MQTT broker after {max_retries} attempts.")

    def disconnect(self) -> None:
        """Stop background network loop and disconnect cleanly."""
        self.client.loop_stop()
        self.client.disconnect()
        self.is_connected = False
        logger.info(f"[{self.client_id}] Disconnected from MQTT broker.")

    def publish(self, topic: str, data: Dict[str, Any], qos: int = 1) -> None:
        """Publish JSON serializable data to an MQTT topic."""
        payload_str = json.dumps(data)
        self.client.publish(topic, payload_str, qos=qos)

    def subscribe(self, topic: str, qos: int = 1) -> None:
        """Subscribe to a specific topic."""
        self.client.subscribe(topic, qos=qos)
        logger.info(f"[{self.client_id}] Subscribed to {topic}")

    def _on_connect(self, client, userdata, flags, reason_code, *args):
        if reason_code == 0:
            self.is_connected = True
            logger.info(f"[{self.client_id}] Successfully connected to broker.")
            # Automatically subscribe to all registered handlers
            for topic in self._callbacks.keys():
                self.client.subscribe(topic, qos=1)
        else:
            logger.error(f"[{self.client_id}] Connection failed with code {reason_code}")

    def _on_disconnect(self, client, userdata, *args):
        self.is_connected = False
        logger.warning(f"[{self.client_id}] Disconnected from broker.")

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception as e:
            logger.error(f"[{self.client_id}] Malformed JSON on {topic}: {e}")
            return

        handler = self._callbacks.get(topic)
        if handler:
            handler(topic, payload)
