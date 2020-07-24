import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import traceback
sys.path.append("..")
from config_vars import *

#################################### METHODS ###################################
def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False

    return commands.check(tocheck)

def strip_string(tostrip, whitelist):
    # for discord channel creation
    stripped = ''.join([ch for ch in tostrip if ch in whitelist])
    return stripped.strip()

# Sorts the rankings array by number of points (do this when adding person(s))
def sort_by_ranking():
    print('Need Functionality Here')

def getChallenges(url, username, password):
    #whitelist = set(string.ascii_letters+string.digits+' '+'-'+'!'+'#'+'$'+'_'+'['+']'+'('+')'+'?'+'@'+'+'+'<'+'>')
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

        challenges = {}
        if all_challenges['success'] == True:
            for chall in all_challenges['data']:
                cat = chall['category']
                challname = chall['name']
                value = chall['value']
                chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
                if cat in challenges.keys():
                    challenges[cat].append(chall_entry)
                else:
                    challenges[cat] = [chall_entry]
        else:
            raise Exception("Error making request")

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

                # Change challenge solved info if solved by team
                for i in range(len(challenges[cat])):
                    if challname == challenges[cat][i]['name']:
                        challenges[cat][i]['solved'] = True
                        challenges[cat][i]['solver'] = solver

        return challenges

#################################### CLASSES ###################################
class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class CredentialsNotFound(Exception):
    pass
class NonceNotFound(Exception):
    pass

class CTF(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_ready(self):
        print('*** CTF Cog Loaded ***')

    @commands.group()
    async def ctf(self, ctx):
        if ctx.invoked_subcommand is None:
            ctf_commands = list(set([c.qualified_name for c in CTF.walk_commands(self)][1:]))
            await ctx.send("Current ctf commands are: \n```\n{0}```".format('\n'.join(ctf_commands)))

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    async def create(self, ctx, name):
        try:
            sconf = serverdb[str(ctx.guild.id) + '-CONF']
            servcat = sconf.find_one({'name': "category_name"})['ctf_category']
        except:
            servcat = "CTF"

        category = discord.utils.get(ctx.guild.categories, name=servcat)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servcat)
            category = discord.utils.get(ctx.guild.categories, name=servcat)

        ctf_name = strip_string(name, set(string.ascii_letters + string.digits + ' ' + '-')).replace(' ', '-').lower()
        await ctx.guild.create_text_channel(name=ctf_name, category=category)
        server = teamdb[str(ctx.guild.id)]
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
        teamdb[str(ctx.guild.id)].remove({'name': str(ctx.message.channel)})
        await ctx.send(f"`{str(ctx.message.channel)}` deleted from db")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def archive(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        await role.delete()
        await ctx.send(f"`{role.name}` role deleted, archiving channel.")
        try:
            sconf = serverdb[str(ctx.guild.id) + '-CONF'] # put this in a try/except, if it doesn't exist set default to CTF
            servarchive = sconf.find_one({'name': "archive_category_name"})['archive_category']
        except:
            servarchive = "ARCHIVE"

        category = discord.utils.get(ctx.guild.categories, name=servarchive)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servarchive)
            category = discord.utils.get(ctx.guild.categories, name=servarchive)
        await ctx.message.channel.edit(syncpermissoins=True, category=category)

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def join(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.add_roles(role)
        await ctx.send(f"{user} has joined the {str(ctx.message.channel)} team!")

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def leave(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.remove_roles(role)
        await ctx.send(f"{user} has left the {str(ctx.message.channel)} team.")

    @ctf.group()
    @in_ctf_channel()
    async def challenge(self, ctx):
        pass

    @commands.bot_has_permissions(manage_messages=True)
    @commands.has_permissions(manage_messages=True)
    @ctf.command()
    @in_ctf_channel()
    async def setcreds(self, ctx, username, password, site):
        pinned = await ctx.message.channel.pins()
        for pin in pinned:
            if "CTF credentials set." in pin.content:
                await pin.unpin()
        message = "CTF credentials set. \n**Username:**\t` {0} ` ".format(username) + \
                  "\n**Password:**\t` {0} ` \n**Website:**\t` {1} `".format(password, site)
        msg = await ctx.send(message)
        await msg.pin()

    @commands.bot_has_permissions(manage_messages=True)
    @ctf.command()
    @in_ctf_channel()
    async def creds(self, ctx):
        pinned = await ctx.message.channel.pins()
        try:
            info = CTF.get_creds(pinned)
            message = "**Username:**\t` {} ` ".format(info[0]) + \
                      "\n**Password:**\t` {} ` \n**Website:**\t` {} `".format(info[1], info[2])
            await ctx.send(message)
            #await ctx.send(f"name:`{user_pass[0]}` password:`{user_pass[1]}`")
        except CredentialsNotFound as cnfm:
            await ctx.send(cnfm)

    @staticmethod
    def get_creds(pinned):
        for pin in pinned:
            if "CTF credentials set." in pin.content:
                vals = pin.content.split(" \n")
                info = [vals[1].split(" ")[1], vals[2].split(" ")[1], vals[3].split(" ")[1]]
                return info
        raise CredentialsNotFound("Set credentials with `>ctf setcreds \"username\" \"password\"`")

    #@challenge.command()
    #@in_ctf_channel()
    @staticmethod
    async def pull(self, ctx, url):
        try:
            try:
                pinned = await ctx.message.channel.pins()
                user_pass = CTF.get_creds(pinned)
            except CredentialsNotFound as cnfm:
                await ctx.send(cnfm)
            ctfd_challs = getChallenges(url, user_pass[0], user_pass[1])
            ctf = teamdb[str(ctx.guild.id)].find_one({'name': str(ctx.message.channel)})
            try: # If there are existing challenges already...
                challenges = ctf['challenges']
                challenges.update(ctfd_challs)
            except:
                challenges = ctfd_challs
            ctf_info = {'name': str(ctx.message.channel),
            'challenges': challenges
            }
            teamdb[str(ctx.guild.id)].update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
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

    @challenge.command()
    @in_ctf_channel()
    async def list(self, ctx):
        pinned = await ctx.message.channel.pins()
        info = CTF.get_creds(pinned)
        print("{}".format(info))
        CTF.pull(self, ctx, info[2])
        print("after pull")

        ctf_challenge_list = []
        server = teamdb[str(ctx.guild.id)]
        ctf = server.find_one({'name': str(ctx.message.channel)})
        try:
            ctf_challenge_list = []
            message = ""
            for k, v in ctf['challenges'].items():
                message += "- {0}\n".format(k)
                for chall in v:
                    message += "[{0}]({1}): ".format(chall['name'], chall['points'])
                    if chall['solved'] == True:
                        message += "Solved by {0}\n".format(chall['solver'])
                    else:
                        message += "Unsolved\n"
                message += "\n"

            await ctx.send("```md\n{0}```".format(message))
        except:
            traceback.print_exc()

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(CTF(bot))
