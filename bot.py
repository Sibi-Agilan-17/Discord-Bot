import asyncio
import datetime
import discord
import importlib.util
import json
import logging
import platform
import os
import random
import sys

from discord import Message, DiscordException
from discord.utils import MISSING, setup_logging
from discord.ext import commands, tasks
from discord.ext.commands import errors
from logging import INFO, WARNING, ERROR, CRITICAL
from typing import Any, Optional

__all__ = (
	'Bot',
	'pre_checks'
)

MINIMUM_PYTHON_VERSION = (3, 9)


class DB:
	def __init__(self, path=None):
		self._path = path if path else './'
		self.data = {}

	async def connect(self) -> bool:
		with open(self._path + 'db.json', 'r') as f:
			data = json.load(f)

		with open(self._path + 'db.json', 'w') as f:
			json.dump(data, f)

		self.data = data
		return data not in ({}, None)

	async def update_cache(self) -> bool:
		with open(self._path + 'db.json', 'r') as f:
			data = json.load(f)

		with open(self._path + 'db.json', 'w') as f:
			json.dump(data, f)

		self.data = data
		return data not in ({}, None)

	async def get_blacklisted_users(self) -> list[int]:
		return self.data['blacklisted_users']

	async def add_blacklist(self, user_id: int):
		...


class Bot(commands.AutoShardedBot):
	server_count: int = 0
	member_count: int = 0
	log_file = 'discord.log'
	path = 'cogs'

	_is_sleeping: bool = False  # Halts command processing when set to True

	def __init__(self, **kwargs):
		self.db = DB()
		self.COGS = []
		self._is_sleeping = True
		self.token = kwargs.get('token')
		self.start_time = datetime.datetime.utcnow()
		self.last_restart = datetime.datetime.utcnow()
		self.log_handler = logging.FileHandler(filename=self.log_file, encoding='utf-8', mode='w')
		self.cache = {
			'blacklisted': []
		}

		super().__init__(
			command_prefix=commands.when_mentioned_or(
				kwargs.get('command_prefix') if kwargs.get('command_prefix') else ''),
			intents=kwargs.get('intents') if isinstance(kwargs.get('intents'),
														discord.Intents) else discord.Intents.default(),
			help_command=kwargs.get('help_command'),
			token=kwargs.get('token'))

	#
	#  Events
	#

	async def on_ready(self):
		self.last_restart = datetime.datetime.utcnow()

		if self._ready is not MISSING:
			await self._ready.wait()

		await self.change_presence()

		await self.log(f'Logged in as {self.user.name}#{self.user.discriminator}')
		await self.log(f'discord.py API version: {discord.__version__}')
		await self.log(f'Python version: {platform.python_version()}')
		await self.log(f'Running on {platform.system()} {platform.release()} {os.name}')
		await self.log('------------------------------')

		await self.db.update_cache()
		self.cache['blacklisted'] = await self.db.get_blacklisted_users()

		self._is_sleeping = False

	async def on_message(self, message: Message, /) -> None:
		if not self._is_sleeping:  # Similar to `self.process_commands()`
			if message.author.bot or message.author.id in self.cache['blacklisted']:
				return

			ctx = await self.get_context(message)
			# the type of the invocation context's bot attribute will be correct
			# await self.invoke(ctx)  # type: ignore

			if ctx.command is not None:
				self.dispatch('command', ctx)
				try:
					if await self.can_run(ctx, call_once=True):
						await ctx.command.invoke(ctx)
					else:
						raise errors.CheckFailure('The global check once functions failed.')
				except errors.CommandError as exc:
					await ctx.command.dispatch_error(ctx, exc)
				else:
					self.dispatch('command_completion', ctx)
			elif ctx.invoked_with:
				exc = errors.CommandNotFound(f'Command "{ctx.invoked_with}" is not found')
				self.dispatch('command_error', ctx, exc)

	async def on_command_error(self, context, exception: discord.ext.commands.CommandError, /) -> None:
		if context.command and context.command.has_error_handler():
			return

		if context.cog and context.cog.has_error_handler():
			return

		await self.log('')
		logging.error('Ignoring exception in command %s', commands.command, exc_info=exception)

	async def on_error(self, event_method: str, /, *args: Any, **kwargs: Any) -> None:
		logging.error('Ignoring exception in %s', event_method)

	async def on_command_completion(self, context: commands.Context) -> None:
		full_command_name = context.command.qualified_name
		split = full_command_name.split(" ")
		executed_command = str(split[0])

		if context.guild is not None:
			await self.log(
				f"Executed {executed_command} command in {context.guild.name} (ID: {context.guild.id}) by {context.author} (ID: {context.author.id})"
			)
		else:
			await self.log(
				f"Executed {executed_command} command by {context.author} (ID: {context.author.id}) in DMs"
			)

	#
	#  Cog controls
	#

	async def load_all(self) -> tuple[str, Exception]:
		"""
		Loads all cogs in the given directory

		:return: tuple(cog path + filename, exception raised (if any))
		"""
		for file in os.listdir('./' + self.path):
			if file.endswith(".py"):
				err = None

				try:
					await super().load_extension(f"{file[:-3]}")
					await self.log(f'Loaded extension {file}')
				except Exception as e:
					await self.log(f'Failed to load extension {file}', level=WARNING)
					err = e

				self.COGS.append(f"{self.path}.{file[:-3]}")
				yield f"{self.path}.{file[:-3]}", err

	async def unload_all(self) -> tuple[str, Exception]:
		"""
		Similar to `load_all`, except it unloads all

		:return: tuple(cog path + filename, exception raised (if any))
		"""
		for cog in list(self.COGS):
			err = None
			try:
				await super().unload_extension(cog)
				await self.log(f'Unloaded extension {cog}')
			except Exception as e:
				await self.log(f'Failed to unload extension {cog}', level=WARNING)
				err = e

			self.COGS.remove(cog)
			yield cog, err

	async def load_cog(self, cog: str, *, package=None) -> tuple[str, Exception]:
		err = None

		try:
			name = self._resolve_name(cog, package)
			if name in self.__extensions:
				raise errors.ExtensionAlreadyLoaded(name)

			spec = importlib.util.find_spec(name)
			if spec is None:
				raise errors.ExtensionNotFound(name)

			await self._load_from_module_spec(spec, name)

			await self.log(f'Loaded extension {cog}')
		except Exception as e:
			await self.log(f'Failed to load extension {cog}', level=WARNING)
			err = e

		self.COGS.append(cog)
		return cog, err

	async def unload_cog(self, cog: str, *, package=None) -> tuple[str, Exception]:
		err = None

		try:
			name = self._resolve_name(cog, package)
			lib = self.__extensions.get(name)
			if lib is None:
				raise errors.ExtensionNotLoaded(name)

			await self._remove_module_references(lib.__name__)
			await self._call_module_finalizers(lib, name)

			await self.log(f'Unloaded extension {cog}')
		except Exception as e:
			await self.log(f'Failed to unload extension {cog}', level=WARNING)
			err = e

		self.COGS.remove(cog)
		return cog, err

	@staticmethod
	async def log(text: str, level=INFO) -> None:
		if level == INFO:
			return logging.info(text)

		if level == WARNING:
			return logging.warning(text)

		if level == CRITICAL:
			return logging.critical(text)

		if level == ERROR:
			return logging.error(text)

	def run(self, load_cogs: Optional[bool] = True, *args, **kwargs) -> None:
		if load_cogs:
			self.load_all()

		if not self.token:
			self.token = input('Enter bot token:')

		async def runner():
			async with self:
				if self.loop is discord.client._LoopSentinel():
					await self._async_setup_hook()

				token = self.token.strip()

				data = await self.http.static_login(token)
				self._connection.user = discord.ClientUser(state=self._connection, data=data)
				self._application = await self.application_info()
				if self._connection.application_id is None:
					self._connection.application_id = self._application.id

				if not self._connection.application_flags:
					self._connection.application_flags = self._application.flags

				await self.login(self.token)
				await self.connect(reconnect=True)

		setup_logging(
			handler=self.log_handler,
			formatter=MISSING,
			level=MISSING,
			root=MISSING,
		)

		try:
			asyncio.run(runner())
		except KeyboardInterrupt:
			print('KeyboardInterrupt: Terminating event loop')
			# nothing to do here
			# `asyncio.run` handles the loop cleanup
			# and `self.start` closes all sockets and the HTTPClient instance.
			return

	#
	#  Embeds
	#

	async def generate_embed(self, **kwargs) -> discord.Embed:
		em = discord.Embed(**kwargs)
		em.set_footer(text=f'Latency: {self.gateway_latency}ms')
		return em

	async def danger_embed(self, **kwargs) -> discord.Embed:
		return await self.generate_embed(colour=discord.Colour.red(), **kwargs)

	failure_embed = danger_embed

	async def not_allowed_embed(self, **kwargs) -> discord.Embed:
		em = await self.danger_embed(**kwargs)
		em.title = 'Not allowed!' if not kwargs.get('title') else kwargs.get('title')
		return em

	async def success_embed(self, **kwargs) -> discord.Embed:
		if not kwargs.get('title'):
			kwargs['title'] = 'Success!'

		return await self.generate_embed(colour=discord.Colour.green(), **kwargs)

	async def random_colour_embed(self, **kwargs) -> discord.Embed:
		return await self.generate_embed(colour=random.randint(0, 255 ** 3), **kwargs)

	async def embed_from_dict(self, data: dict, **kwargs) -> discord.Embed:
		em = await self.generate_embed(**kwargs)

		for name, value in data.items():
			em.add_field(name=name, value=value, inline=True)

		return em

	random_color_embed = random_colour_embed

	# Shards

	async def on_shard_connect(self, shard_id):
		await self.log(f'Connected to shard {shard_id}')

	async def on_shard_disconnect(self, shard_id):
		await self.log(f'Disconnected from shard {shard_id}')

	#  ------------

	async def blacklist_user(self, user_id):
		await self.db.add_blacklist(user_id)

		if user_id not in self.cache['blacklist']:
			self.cache['blacklist'].append(user_id)
			await self.update_cache()

	async def update_cache(self):
		await self.db.update_cache()
		self.cache = self.db.data

		await self._loop()

	async def restart(self, *, level: int = 1):
		if level == 1:
			self._is_sleeping = True

			if isinstance(self, commands.AutoShardedBot):
				try:
					for shard in self.shards:
						await self.get_shard(shard).reconnect()
				except DiscordException:
					level += 1
				self._is_sleeping = False
				return
			else:
				level += 1

		if level == 2:
			self._is_sleeping = True

			try:
				for a in self.cogs:
					await self.unload_cog(a)
					await self.load_cog(a)
			except DiscordException:
				level += 1
			self._is_sleeping = False
			return

		if level == 3:
			self._is_sleeping = True

			self._closed = False
			self._ready.clear()
			self._connection.clear()
			self.http.clear()

			while True:
				if self._ready is not MISSING:
					await self._ready.wait()
					break

			self._is_sleeping = False

		if level < 0:
			await self.stop()
			sys.exit(-1)

	async def stop(self):
		#  NOTE: Should close all threads & processes
		await self.change_presence(status=discord.Status.do_not_disturb)
		await self.sleep(secs=5)  # To stop all current activities
		self._loop.stop()

		for extension in tuple(self.__extensions):
			try:
				await self.unload_extension(extension)
			except (Exception, DiscordException):
				pass

		for cog in tuple(self.__cogs):
			try:
				await self.remove_cog(cog)
			except (Exception, DiscordException):
				pass

		if self.is_closed():
			return

		await self._connection.close()
		self._closed = True

		if self.ws is not None and self.ws.open:
			await self.ws.close(code=1000)

		await self.http.close()

		if self._ready is not MISSING:
			self._ready.clear()

		self.loop = MISSING

	async def logout(self):
		await self.http.logout()

	async def sleep(self, *, secs: int = 5) -> None:
		if not self._is_sleeping:
			self._is_sleeping = True
			await asyncio.sleep(secs)
			self._is_sleeping = False
			return

		await asyncio.sleep(5)
		self._is_sleeping = False

	@tasks.loop(minutes=5)
	async def _loop(self) -> None:
		await self.db.update_cache()

		self.gateway_latency = round(self.latency * 1000, 2)
		self.server_count = len(self.guilds)
		self.member_count = len(set(self.get_all_members()))

		if self.gateway_latency > 1200:  # Added extra 200 ms for buffer
			print(f'Latency {self.gateway_latency}')

	async def setup_hook(self) -> None:
		await self.db.connect()
		self._loop.start()


def pre_checks():
	if not discord.__version__.startswith('2.2'):
		print('Older versions of discord.py are not supported')
		print('Please update your discord.py version to 2.2+ ')
		logging.info('discord.py needs updating to version 2.2+')

		sys.exit(-1)

	if not sys.version_info >= MINIMUM_PYTHON_VERSION:
		print('Older versions of python are not supported')
		print('Please upgrade your python version to {MINIMUM_PYTHON_VERSION[0]}.{MINIMUM_PYTHON_VERSION[1]}+')
		logging.info('python needs updating to version {MINIMUM_PYTHON_VERSION[0]}.{MINIMUM_PYTHON_VERSION[1]}+')

		sys.exit(-1)
