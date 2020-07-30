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
def getPoints(url, username, password):
    fingerprint = "Powered by CTFd"
    s = requests.session()
    if url[-1] == "/": url = url[:-1]
    r = s.get(f"{url}/login")
    if fingerprint not in r.text:
        raise InvalidProvider("CTF is not based on CTFd, cannot pull challenges.")
    else:
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here, my theory is that it is different versions of CTFd
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login, please >report this along with the ctf url.")
        r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials")

    # Get point information
    r_chals = s.get(f"{url}/api/v1/challenges")
    all_challenges = r_chals.json()

class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.group()
    async def leaderboard(self, ctx):
        if ctx.invoked_subcommand is None:
            l_commands = list(set([c.qualified_name for c in CTF.walk_commands(self)][1:]))
            await ctx.send("Current ctf commands are: \n```\n{0}```".format('\n'.join(l_commands)))

    @commands.command()
    async def rank(self, ctx):
        print('Need Functionality Here')

    @commands.command()
    async def top10(self, ctx):
        print('Need Functionality Here')
        #message = "Points: {}".format(points)
        #await ctx.send("HI")

def setup(bot):
    bot.add_cog(Leaderboard(bot))
