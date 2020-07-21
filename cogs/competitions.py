import discord
from discord.ext import commands, tasks

class Competitions(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_ready(self):
        print('*** Competitions Cog Loaded ***')

    @commands.command()
    async def upcoming():
        print('Need Functionality Here')

def setup(bot):
    bot.add_cog(Competitions(bot))
