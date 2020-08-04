import discord
from discord.ext import commands, tasks
import string
import json
import requests
import sys
import traceback
sys.path.append("..")
from config_vars import *

################################ DATA STRUCTURES ###############################
points = {}
num_ctfs = {}
ranking = []

#################################### METHODS ###################################
class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.group()
    async def rank(self, ctx):
        if ctx.invoked_subcommand is None:
            l_commands = list(set([c.qualified_name for c in Leaderboard.walk_commands(self)][1:]))
            await ctx.send("Current rank commands are: \n```\n{0}```".format('\n'.join(l_commands)))

    @rank.command()
    async def me(self, ctx):
        print('Need Functionality Here')

    @rank.command()
    async def top5(self, ctx, cat=None):
        user = ctx.message.author
        server = client[str(ctx.guild.name).replace(' ', '-')]
        info = server['info'].find_one({'name': str(ctx.guild.name)})
        if not cat is None:
            await ctx.send("Not supported yet")
            return

        count = 0
        message = "**Top 5 Overall Scores** - {}\n".format(ctx.guild.name)
        for member in info['ranking']:
            if count < 5:
                message += "{}. {}: {}\n".format(count + 1, member['name'], member['score'])
            else:
                break
            count += 1

        if not message == "":
            await ctx.send(message)

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(Leaderboard(bot))
