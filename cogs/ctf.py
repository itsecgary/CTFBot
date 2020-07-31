import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import traceback
from datetime import *
from config_vars import *
sys.path.append("..")


#################################### METHODS ###################################
def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not str(ctx.channel.type) == "private" and \
           client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False

    return commands.check(tocheck)

def get_challenges_CTFd(ctx, url, username, password, s):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            raise NonceNotFound("Was not able to find the nonce token from login, please >report this along with the ctf url.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challenges")
    all_challenges = r_chals.json()

    # Get team solves
    r_solves = s.get(f"{url}/api/v1/teams/me/solves")
    team_solves = r_solves.json()
    if 'success' not in team_solves:
        # ctf is user based.  There is a flag on CTFd for this (userMode), but it is not present in all versions, this way seems to be.
        r_solves = s.get(f"{url}/api/v1/users/me/solves")
        team_solves = r_solves.json()

    # Variables
    challenges = {}
    total_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']

    # Add all challenges
    if all_challenges['success'] == True:
        for chall in all_challenges['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['value']
            total_points += value
            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add total points to db
    ctf_info = {'name': str(ctx.message.channel), 'total points': total_points}
    server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)

    # Add team solves
    if team_solves['success'] == True:
        for solve in team_solves['data']:
            # Get challenge info
            cat = solve['challenge']['category']
            challname = solve['challenge']['name']
            solver = solve['user']

            # Get user info
            r_user = s.get(f"{url}/api/v1/users/{solver}")
            user_profile = r_user.json()
            solver = user_profile['data']['name']
            # NEED TO SEARCH THE ALIASES

            # Change challenge solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True
                    challenges[cat][i]['solver'] = solver

    return challenges

def get_challenges_rCTF(ctx, url, token, s):
    r = s.get(f"{url}/login")
    #print(r)
    r = s.post(f"{url}/login", data={"teamToken": token})
    if "Your token is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get challenge information
    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "https://2020.redpwn.net/challs",
        "Authorization": "Bearer ytT+oaVylGSA5AndOlhfo6tQehRt0PKQ59KYd8Wi7n4cDmpT7/eK60WzCFBaer/vlSOuIt6NMV7P2kCRtPS+RsqnObhgnflD4Lcsrs4tROu7Qi8hrvl5KYLWp/yd"
    }
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()

    # Get team solves
    r_solves = s.get(f"{url}/api/v1/users/me", headers=heads)
    team_solves = r_solves.json()

    # Variables
    challenges = {}
    total_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']

    # Add all challenges
    if all_challs['kind'] == "goodChallenges":
        for chall in all_challs['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['points']
            total_points += value
            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add total points to db
    ctf_info = {'name': str(ctx.message.channel), 'total points': total_points}
    server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)

    # Add team solves
    if team_solves['kind'] == "goodUserData":
        print("goodUserData")
        for solve in team_solves['data']['solves']:
            # Get challenge info
            cat = solve['category']
            challname = solve['name']

            # Change challenge solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True

    return challenges

#################################### CLASSES ###################################
class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class NonceNotFound(Exception):
    pass

class CTF(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.creds = {} # Stores credentials locally (not in database)
        self.current = [] # Stores started ctfs
        self.get_info.start()

    @tasks.loop(seconds=10.0)
    async def get_info(self):
        #print("Running Task Get_Info")
        now = datetime.utcnow()
        unix_now = int(now.replace(tzinfo=timezone.utc).timestamp())
        running = False

        for ctf in ctfs.find():
            if ctf['start'] < unix_now and ctf['end'] > unix_now: # Check if the ctf is running
                running = True
                if not ctf['name'] in self.current: # we only want to do this once
                    self.current.append(ctf['name'])
                    # GET INFO

    @commands.group()
    async def ctf(self, ctx):
        if ctx.invoked_subcommand is None:
            ctf_commands = list(set([c.qualified_name for c in CTF.walk_commands(self)][1:]))
            await ctx.send("Current ctf commands are: \n```\n{0}```".format('\n'.join(ctf_commands)))

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    async def create(self, ctx, name):
        servcat = "CTF"
        category = discord.utils.get(ctx.guild.categories, name=servcat)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servcat)
            category = discord.utils.get(ctx.guild.categories, name=servcat)

        whitelist = set(string.ascii_letters + string.digits + ' ' + '-')
        ctf_name = ''.join([ch for ch in name if ch in whitelist]).strip().replace(' ', '-').lower()
        await ctx.guild.create_text_channel(name=ctf_name, category=category)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        await ctx.guild.create_role(name=ctf_name, mentionable=True)
        ctf_info = {'name': ctf_name, "text_channel": ctf_name}
        server.update({'name': ctf_name}, {"$set": ctf_info}, upsert=True)
        await ctx.message.add_reaction("✅")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def delete(self, ctx):
        # Delete role from server, delete entry from db
        try:
            role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
            await role.delete()
            await ctx.send(f"`{role.name}` role deleted")
        except: # role most likely already deleted with archive
            pass
        client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].remove({'name': str(ctx.message.channel)})
        await ctx.send(f"`{str(ctx.message.channel)}` deleted from db")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def archive(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        await role.delete()
        await ctx.send(f"`{role.name}` role deleted, archiving channel.")
        servarchive = "ARCHIVE"
        category = discord.utils.get(ctx.guild.categories, name=servarchive)

        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servarchive)
            category = discord.utils.get(ctx.guild.categories, name=servarchive)
        await ctx.message.channel.edit(syncpermissions=True, category=category)

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def join(self, ctx, alias):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.add_roles(role)
        await ctx.send(f"{user} has joined the {str(ctx.message.channel)} team!")

        server = client[str(ctx.guild.name).replace(' ', '-')]['members']
        member = server.find_one({'name': str(user)})

        arr = member['aliases']
        if arr == []:
            arr = [alias]
        else:
            arr.append(alias)

        member_info = {'name': str(user), 'aliases': arr}
        server.update({'name': str(user)}, {"$set": member_info}, upsert=True)

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def leave(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.remove_roles(role)
        await ctx.send(f"{user} has left the {str(ctx.message.channel)} team.")

    @ctf.command()
    async def setcreds(self, ctx, username, password, site, guild_name, channel=None):
        if channel == None:
            channel = guild_name
            guild_name = site
            site = password
            password = None

        replace_msg = ""
        if self.creds and (str(guild_name) + "." + str(channel)) in self.creds:
            replace_msg += "Replacing **{}**'s creds".format(self.creds[str(guild_name) + "." + str(channel)]['user'])

        if str(ctx.message.channel.type) == "private":
            channels = {}
            for g in self.bot.guilds:
                if g.name == guild_name:
                    channels = g.channels

            if channels:
                channel_id = 0
                for h in channels:
                    if h.name == channel:
                        channel_id = h.id
                if not channel_id == 0:
                    if password == None:
                        self.creds[str(guild_name) + "." + str(channel)] = {
                            "token": username,
                            "site": site
                        }
                        message = "CTF credentials set. \n**Token:**\t ".format(username) + \
                              "` * * * * * * * * ` \n**Website:**\t` {} `".format(site)
                    else:
                        self.creds[str(guild_name) + "." + str(channel)] = {
                            "user": username,
                            "pass": password,
                            "site": site
                        }
                        message = "CTF credentials set. \n**Username:**\t` {0} ` ".format(username) + \
                              "\n**Password:**\t` * * * * * * * * ` \n**Website:**\t` {} `".format(site)

                    # Get rid of pins
                    ch = self.bot.get_channel(channel_id)
                    pinned = await ch.pins()
                    for pin in pinned:
                        if "CTF credentials set." in pin.content:
                            await pin.unpin()

                    # Send replace message if need be and send real message
                    if not replace_msg == "":
                        await ch.send(replace_msg)
                    msg = await ch.send(message)
                    await msg.pin()
                else:
                    await ctx.send("Channel is incorrect or doesn't exist.")
            else:
                await ctx.send("Guild is incorrect or doesn't exist.")
        else:
            await ctx.send("DM me to set the credentials")

    @staticmethod
    async def pull(self, ctx, url2):
        fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
        url = url2
        try:
            if not self.creds[str(ctx.guild.name) + "." + str(ctx.message.channel)]:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))
            if fingerprints[0] in r.text:
                user = self.creds[str(ctx.guild.name) + "." + str(ctx.message.channel)]["user"]
                password = self.creds[str(ctx.guild.name) + "." + str(ctx.message.channel)]["pass"]
                ctfd_challs = get_challenges_CTFd(ctx, url, user, password, s)
            elif fingerprints[1] in r.text:
                token = self.creds[str(ctx.guild.name) + "." + str(ctx.message.channel)]["token"]
                ctfd_challs = get_challenges_rCTF(ctx, url, token, s)
            elif fingerprints[2] in r.text:
                ctfd_challs = 0 # TODO - Implement CTFx functionality
            else:
                raise InvalidProvider("CTF is not based on CTFd, CTFx, or rCTF - cannot pull challenges.")

            ctf_info = {'name': str(ctx.message.channel), 'challenges': ctfd_challs}
            server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
            server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
            await ctx.message.add_reaction("✅")
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctfd.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_ctf_channel()
    async def challenges(self, ctx):
        await CTF.pull(self, ctx, self.creds[str(ctx.guild.name) + "." + str(ctx.message.channel)]["site"])

        ctf_challenge_list = []
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        try:
            ctf_challenge_list = []
            message = ""
            for k, v in ctf['challenges'].items():
                message += "- {0}\n".format(k)
                for chall in v:
                    message += "[{0}]({1}): ".format(chall['name'], chall['points'])
                    if chall['solved'] == True:
                        message += "Solved - {0}\n".format(chall['solver'])
                    else:
                        message += "Unsolved\n"
                message += "\n"

            await ctx.send("```md\n{0}```".format(message))
        except:
            traceback.print_exc()

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(CTF(bot))
