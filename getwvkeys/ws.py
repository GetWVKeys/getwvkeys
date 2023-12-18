import ast
import asyncio
import json
import time
import uuid
import websockets
from getwvkeys import libraries
from getwvkeys.utils import OPCode


class WebSocketManager:
    def __init__(self, app, library, db, host: str, port: str) -> None:
        self.app = app
        self.library = library
        self.db = db
        self.host = host
        self.port = port
        self.server = None
        self.clients: set[websockets.WebSocketServerProtocol] = set()
        self.queue = {}

    async def start_server(self):
        # Start the WebSocket server
        self.server = await websockets.serve(self.handle_client, self.host, self.port)
        print(f"WebSocket server started at ws://{self.host}:{self.port}")

    async def handle_client(self, websocket, path):
        print(f"Client connected: {websocket}")
        self.clients.add(websocket)
        try:
            async for message in websocket:
                print(f"Received message from client: {message}")
                parsed = json.loads(message)
                op = parsed.get("op")
                d = parsed.get("d")
                req_id = parsed.get("req_id")

                if op == OPCode.DISABLE_USER.value:
                    user_id = d.get("user_id")
                    if not user_id:
                        await self.publish_error(req_id, "No user_id found in message")
                        return
                    with self.app.app_context():
                        try:
                            libraries.User.disable_user(self.db, user_id)
                            await self.publish_response(req_id)
                            return
                        except Exception as e:
                            await self.publish_error(req_id, "Error disablng user {}: {}".format(user_id, e))
                            return
                elif op == OPCode.DISABLE_USER_BULK.value:
                    user_ids = d.get("user_ids")
                    if not user_ids:
                        await self.publish_error(req_id, "No user_ids found in message")
                        return
                    with self.app.app_context():
                        try:
                            libraries.User.disable_users(self.db, user_ids)
                            await self.publish_response(
                                req_id
                            )
                            return
                        except Exception as e:
                           await self.publish_error(req_id, "Error disablng users: {}".format(e))
                           return
                elif op == OPCode.ENABLE_USER.value:
                    user_id = d.get("user_id")
                    if not user_id:
                        await self.publish_error(req_id, "No user_id found in message")
                        return
                    with self.app.app_context():
                        try:
                            libraries.User.enable_user(self.db, user_id)
                            await self.publish_response(
                                req_id
                            )
                            return
                        except Exception as e:
                            await self.publish_error(req_id, "Error enabling user {}: {}".format(user_id, e))
                            return
                elif op == OPCode.KEY_COUNT.value:
                    with self.app.app_context():
                        await self.publish_response(req_id, self.library.get_keycount())
                        return
                elif op == OPCode.USER_COUNT.value:
                    with self.app.app_context():
                        await self.publish_response(req_id, libraries.User.get_user_count())
                        return
                elif op == OPCode.SEARCH.value:
                    query = d.get("query")
                    if not query:
                        await self.publish_error(req_id, "No query found in message")
                        return
                    with self.app.app_context():
                        try:
                            results = self.library.search(query)
                            results = self.library.search_res_to_dict(query, results)
                            await self.publish_response(req_id, results)
                            return
                        except Exception as e:
                            await self.publish_error(req_id, "Error searching: {}".format(e))
                            return
                elif op == OPCode.UPDATE_PERMISSIONS.value:
                    user_id = d.get("user_id")
                    permissions = d.get("permissions")
                    permission_action = d.get("permission_action")
                    if not user_id or not permissions:
                        self.publish_error(req_id, "No user_id or permissions found in message")
                        return
                    with self.app.app_context():
                        try:
                            user = libraries.User.get(self.db, user_id)
                            if not user:
                                await self.publish_error(req_id, "User not found")
                                return

                            print("Old flags: ", user.flags_raw)
                            user = user.update_flags(permissions, permission_action)
                            print("New flags: ", user.flags_raw)
                            await self.publish_response(
                                req_id
                            )
                            return
                        except Exception as e:
                            await self.publish_error(req_id, "Error updating permissions for {}: {}".format(user_id, e))
                            return
                elif op == OPCode.RESET_API_KEY.value:
                    user_id = d.get("user_id")
                    with self.app.app_context():
                        user = libraries.User.get(self.db, user_id)
                        if not user:
                            await self.publish_error(req_id, "User not found")
                            return
                        try:
                            user.reset_api_key()
                            await self.publish_response(req_id, "API Key has been reset for user {}".format(user.username))
                            return
                        except Exception as e:
                            await self.publish_error(req_id, "Error resetting API Key for {}: {}".format(user.username, str(e)))
                            return
                else:
                   await self.publish_error(req_id, "Unknown OPCode {}".format(op))
                   return
        except websockets.exceptions.ConnectionClosed as e:
            print(f"Client disconnected: {e}")
            self.clients.remove(websocket)
        finally:
            print(f"Client connection closed: {websocket}")

    async def broadcast(self, message):
        # Send a message to all connected clients
        print(f"Broadcasting message to {len(self.clients)} clients")
        await asyncio.gather(*(client.send(message) for client in self.clients))

    def stop_server(self):
        # Stop the WebSocket server
        if self.server:
            self.server.close()
            asyncio.get_event_loop().run_until_complete(self.server.wait_closed())
            print("WebSocket server stopped")

    async def publish_error(self, req_id: str, e):
        """
        Publishes an error response
        """
        print("publishing error")
        payload = {"op": -1, "d": {"error": True, "message": e}, "req_id": req_id}
        await self.broadcast(json.dumps(payload))

    async def publish_response(self, req_id: str, msg=None):
        """
        Publishes a response
        """
        print("publishing response")
        payload = {"op": OPCode.REPLY.value, "d": {"error": False, "message": msg}, "req_id": req_id}
        await self.broadcast(json.dumps(payload))

    
    async def get_response(self, req_id):
        start_time = time.time()
        while self.queue[req_id] is None:
            await asyncio.sleep(0.1)
            now = time.time()
            # timeout after 5 seconds
            if now - start_time > 5:
                raise Exception("Timeout")
        reply = self.queue[req_id]
        data = json.loads(reply)
        op = data.get("op")
        d = data.get("d")
        rmsg = d.get("message")
        if op == OPCode.ERROR.value:
            raise Exception(rmsg)
        return rmsg

    async def publish_packet_async(self, op: OPCode, data: dict = {}):
        corr_id = str(uuid.uuid4())
        self.queue[corr_id] = None
        payload = {
            "op": op.value,
            "d": data
        }
        print(f"Publishing async packet: ", payload)
        self.broadcast(json.dumps(payload))
        res = await self.get_response(corr_id)
        return res
    
    async def publish_packet_sync(self, op: OPCode, data: dict = {}):
        payload = {"op": op.value, "d": data}
        print(f"Publishing sync packet: ", payload)
        await self.websocket.send(json.dumps(payload))
