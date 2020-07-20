import discord
from discord.ext import commands

class Competitions(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def upcoming():
        print('Need Functionality Here')

    @commands.command()


def setup(bot):
    bot.add_cog(Competitions(bot))
