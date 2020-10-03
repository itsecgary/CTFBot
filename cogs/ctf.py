import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import re
import os
import traceback
import help_info
import time as tm
from dateutil.parser import parse
from datetime import *
from config_vars import *
sys.path.append("..")

################################ DATA STRUCTURES ###############################
chall_aliases = {
    "crypto": ["crypto", "cryptography", "aes", "rsa", "encryption", "encoding", "cipher", "ciphers"],
    "forensics": ["forensics", "stego", "steganography", "memory analysis"],
    "misc": ["misc", "other", "miscellaneous", "trivia", "random", "warmup"],
    "osint": ["osint" "open source intelligence"],
    "web exploitation": ["web", "web-exploitation", "web exploitation"],
    "binary exploitation": ["pwn", "pwning", "binary exploitation", "binary-exploitation", "exploitation", "kernel exploitation"],
    "reversing": ["reverse", "reversing", "re", "reverse engineering", "reverse-engineering"],
    "tryhackme": ["htb", "hackthebox", "hack the box", "try hack me", "tryhackme"],
    "cryptocurrency": ["cryptocurrency", "etherium", "coin", "bitcoin", "blockchain", "secure contracts"],
    "network": ["network", "networking", "network analysis", "wireshark", "rf", "pcap"],
    "mobile": ["mobile", "android", "mobile security", "apk"]
}

#################################### METHODS ###################################
def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not (str(ctx.channel.type) == "private") and \
           client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False

    return commands.check(tocheck)

def in_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not str(ctx.channel.type) == "private":
            return True
        else:
            await ctx.send("This command is not available over DM!")
            return False

    return commands.check(tocheck)

def check_aliases(guild, creds, channel_name):
    fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
    server = client[str(guild.name).replace(' ', '-')]['ctfs']
    ctf = server.find_one({'name': channel_name})

    url = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["site"]
    if url[-1] == "/": url = url[:-1]
    s = requests.session()
    r = s.get("{}/login".format(url))
    if fingerprints[0] in r.text:
        user = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["user"]
        password = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["pass"]
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here - possibly due to CTFd versioning
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login. Could not check if aliases are correct.")

        # Login and check if credentials are valid
        r = s.post(f"{url}/login", data={"name": user, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials. Could not check if aliases are correct.")

        # Get aliases for all members
        aliases = []
        members = s.get(f"{url}/api/v1/teams/me").json()['data']['members']
        for m_id in members:
            alias = s.get("{}/api/v1/users/{}".format(url, m_id)).json()
            aliases.append(alias['data']['name'])

        # iterate members in competition and check if they are in aliases
        members_not = []
        for name, attr in ctf['members'].items():
            if not attr['alias'] in aliases:
                members_not.append(name)

        if len(members_not) > 0:
            m = ""
            for mem in members_not:
                it = mem.split("#")
                user = discord.utils.get(guild.members, name = it[0], discriminator = it[1])
                m += user.mention + " "
            m += "\nYou have invalid aliases! "
            m += "Send `>ctf join [alias]` to update your alias or this will not count for your scoring."
            raise InvalidCredentials(m)

    else:
        raise InvalidCredentials("CTF is not based on CTFd - could not check if aliases are correct.")

def calculate(server_name, ctf_name):
    # Fetch Databases
    server = client[server_name.replace(' ', '-')]
    info_db = server['info']
    members = server['members']
    ctf = server['ctfs'].find_one({'name': ctf_name})
    num_members = len(ctf['members'].keys())

    # Calculate scores for each member of competition
    for name, mem_points in ctf['members'].items():
        # Add CTF to competed CTFs
        member = members.find_one({'name': name})
        arr = member['ctfs_competed']
        if arr == []:
            arr = [ctf_name]
        else:
            arr.append(ctf_name)
        length = len(arr)

        # Calculate each category
        for cat, val in mem_points.items():
            if not (cat == "alias") and not (ctf['points'][cat] == 0):
                solved_p = val
                total_p = ctf['points'][cat]
                curr_score = member['ratings'][cat] * (length-1)
                if total_p == 0:
                    score = 0
                else:
                    score = 10*(solved_p/total_p)*(1 + ctf['weight']/100)*(1 + (9 - num_members)/10)

                score = ((score + curr_score)/length)
                if score == 0:
                    score = int(score)
                else:
                    score = score + ((length)/50)
                member['ratings'][cat] = score

        # Calculate overall
        overall = 0
        for cat, val in member['ratings'].items():
            overall += val
        overall = overall/len(member['ratings'].values())

        # Update member's DB and set boolean to True
        server['members'].update({'name': name}, {"$set": {'overall': overall, 'ratings': member['ratings'], 'ctfs_competed': arr}}, upsert=True)
        server['ctfs'].update({'name': ctf_name}, {"$set": {'calculated?': True}}, upsert=True)

    # add overall to rankings
    rankings = {}
    overall_r = []
    already_got = []
    while (len(overall_r) < members.count()):
        highest = -1
        p = None
        for person in members.find():
            if person['overall'] > highest and not person['name'] in already_got:
                highest = person['overall']
                p = person
        already_got.append(p['name'])
        overall_r.append({'name': p['name'], 'score': p['overall']})
    rankings['overall'] = overall_r

    # add each CTF category to rankings
    for cat in chall_aliases.keys():
        arr = []
        already_got = []
        while (len(arr) < members.count()):
            highest = -1
            p = None
            for person in members.find():
                if person['ratings'][cat] > highest and not person['name'] in already_got:
                    highest = person['ratings'][cat]
                    p = person
            already_got.append(p['name'])
            arr.append({'name': p['name'], 'score': p['ratings'][cat]})
        rankings[cat] = arr

    # Update Guild Information
    comp_arr = info_db.find_one({'name': server_name})['competitions']
    if comp_arr == []:
        comp_arr = [ctf_name]
    else:
        comp_arr.append(ctf_name)

    # Update DB with all calculated information
    info_db.update({'name': server_name}, {"$set": {'ranking': rankings, 'competitions': comp_arr, 'num competitions': len(comp_arr)}}, upsert=True)

def get_one_CTFd(ctx, url, username, password, s, chall):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get challenge ID
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    chall_id = -1
    for c_hash in all_challenges['data']:
        if c_hash['name'].lower() == chall.lower():
            chall_id = c_hash['id']
            break

    # If chall name was not found, return with error message
    if chall_id == -1:
        raise InvalidCredentials("Challenge not found")

    # Grab challenge file and attach in message
    challenge_info = s.get("{}/api/v1/challenges/{}".format(url, chall_id)).json()
    return challenge_info

def get_challenges_CTFd(ctx, url, username, password, s):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get information from API
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    team_info = s.get(f"{url}/api/v1/teams/me").json()
    team_solves = s.get(f"{url}/api/v1/teams/me/solves").json()
    if 'success' not in team_solves: # ctf is user based
        team_info = s.get(f"{url}/api/v1/users/me").json()
        team_solves = s.get(f"{url}/api/v1/users/me/solves").json()

    # Variables
    challenges = {}
    point_info = {
        "crypto": 0, "forensics": 0, "misc": 0, "osint": 0,
        "web exploitation": 0, "binary exploitation": 0, "reversing": 0, "tryhackme": 0,
        "cryptocurrency": 0, "network": 0, "mobile": 0, "total": 0
    }
    solved_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
    members = server.find_one({'name': str(ctx.message.channel)})['members']

    # Reset points to 0
    for k, v in members.items():
        for cat, _ in v.items():
            if not cat == "alias": members[k][cat] = 0

    # Add all challenges
    if all_challenges['success'] == True:
        for chall in all_challenges['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['value']
            point_info['total'] += value

            # Add points for category
            for real_chall_name, aliases in chall_aliases.items():
                if cat.lower() in aliases:
                    point_info[real_chall_name] += value
                    break

            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add team solves
    if team_solves['success'] == True:
        for solve in team_solves['data']:
            # Get challenge info
            cat = solve['challenge']['category']
            challname = solve['challenge']['name']
            solver = solve['user']
            value = solve['challenge']['value']
            solved_points += value

            # Get user info
            r_user = s.get(f"{url}/api/v1/users/{solver}")
            user_profile = r_user.json()
            solver = user_profile['data']['name']

            # Add points for member who solved it for specific category
            for name, attr in members.items():
                if attr["alias"] == solver:
                    for real_chall_name, aliases in chall_aliases.items():
                        if cat.lower() in aliases:
                            members[name][real_chall_name] += value
                            break

            # Change challenge_solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True
                    challenges[cat][i]['solver'] = solver

    # Add total points to db
    rank = ""
    if "place" in team_info['data'].keys() and team_info['data']['place']:
        rank += team_info['data']['place']
    ctf_info = {'points': point_info, 'solved points': solved_points,
                'rank': rank, 'members': members}
    #server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
    return challenges

def get_challenges_rCTF(ctx, url, token, s):

    heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
    }
    r = s.post(f"{url}/api/v1/auth/login", json={"teamToken": token}, headers=heads)
    if "Your token is incorrect" in r.text or "badToken" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    r_json = r.json()
    bearer_token = r_json['data']['authToken']

    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "{}/challs".format(url),
        "Authorization": "Bearer {}".format(bearer_token)
    }

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()

    # Get team solves
    r_solves = s.get(f"{url}/api/v1/users/me", headers=heads)
    team_solves = r_solves.json()

    #print(all_challs)
    #print(team_solves)

    # Variables
    challenges = {}
    total_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']

    print(all_challs['kind'])

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

    @tasks.loop(minutes=1.0)
    async def get_info(self):
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        # Get chall info for each running competition
        for guild in self.bot.guilds:
            server = client[str(guild.name).replace(' ', '-')]
            for ctf in server['ctfs'].find():
                # Pull challenges at very START and END of competition
                if ((unix_now - ctf['start'] < 122) and (unix_now - ctf['start'] > 0)) or \
                ((ctf['end'] - unix_now > 0) and (ctf['end'] - unix_now < 122)):
                    # Add name to current array
                    if not ctf['name'] in self.current:
                        self.current.append(ctf['name'])

                    # Check aliases
                    if str(guild.name).replace(' ', '-') + "." + str(ctf['name']) in self.creds:
                        c_id = 0
                        for channel in guild.channels:
                            if channel.name == ctf['name']:
                                print(channel.id)
                                c_id = channel.id
                                break
                        ch = self.bot.get_channel(c_id)
                        try:
                            check_aliases(guild, self.creds, str(ctf['name'])) # Check if all aliases are good!
                            await ch.send("Yep, everyone has correct aliases")
                        except InvalidCredentials as icm:
                            await ch.send(icm)

                # Right after competition ends
                elif unix_now - ctf['end'] < 122:
                    self.current.remove(ctf['name'])
                    c_id = 0

                    # Get channel id to send info
                    c_id = 0
                    for channel in guild.channels:
                        if channel.name == ctf['name']:
                            c_id = channel.id
                            break
                    ch = self.bot.get_channel(c_id)

                    # Display Statistics from competition
                    # Add simple team stats
                    ti = "Stats from {}".format(ctf['name'])
                    des = "**Members:** "
                    for name, v in ctf['members'].items():
                        des += "{}, ".format(name.split("#")[0])
                    des = des[:-2]
                    val = "{} out of {} points".format(ctf['solved points'], ctf['points']['total'])
                    rank = ctf['rank']
                    if rank == "": rank = "???"
                    emb = discord.Embed(title=ti, description=des, colour=10181046)
                    emb.add_field(name="Score", value=val, inline=True)
                    emb.add_field(name="Place", value=rank, inline=True)
                    emb.set_thumbnail(url=str(ctf['logo']))
                    await ch.send(embed=emb)

                    # Add all members stats
                    for name, attr in ctf['members'].items():
                        total = 0
                        ti = "{}'s Details".format(name.split('#')[0])
                        emb = discord.Embed(title=ti, description="[scored] / [total]", colour=10181046)
                        for cat, val in attr.items():
                            if not cat == "alias" and not val == 0:
                                nm = ' '.join([c.capitalize() for c in cat.split(' ')])
                                val2 = f"{val}" + " / {}".format(ctf['points'][cat])
                                emb.add_field(name=nm, value=val2, inline=False)
                                total += val

                        emb.set_thumbnail(url=(server['members'].find_one({'name': name})['pfp']))
                        emb.add_field(name="Total Points", value=total, inline=True)
                        await ch.send(embed=emb)
                        print("got user embed - {}".format(name))

                    # Calculate scores
                    calculate(str(guild.name), ctf)

    @commands.group()
    async def ctf(self, ctx):
        if ctx.invoked_subcommand is None:
            await ctx.channel.send("Invalid command. Run `>help ctf` for information on **ctf** commands.")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    async def create(self, ctx, link):
        servcat = "CTF"
        category = discord.utils.get(ctx.guild.categories, name=servcat)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servcat)
            category = discord.utils.get(ctx.guild.categories, name=servcat)

        # Parse CTFTime Link
        if link[-1] == "/": link = link[:-1]
        event_id = link.split("/")[-1]
        link = "https://ctftime.org/api/v1/events/{}/".format(event_id)
        head = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0'}

        # Get and parse JSON data for competition
        r_event = requests.get(link, headers=head)

        # Error message when CTFTime is down and doesn't do anything
        if r_event.status_code == 404:
            await ctx.channel.send("CTFTime is currently down. Try again later!")
            return

        event_json = r_event.json()

        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        (ctf_start, ctf_end) = (parse(event_json['start'].replace('T', ' ').split('+', 1)[0]), parse(event_json['finish'].replace('T', ' ').split('+', 1)[0]))
        (unix_start, unix_end) = (int(ctf_start.replace(tzinfo=timezone.utc).timestamp()), int(ctf_end.replace(tzinfo=timezone.utc).timestamp()))
        (ctf_hours, ctf_days) = (str(event_json["duration"]["hours"]), str(event_json["duration"]["days"]))
        ctf_info = {
            "name": event_json["title"].replace(' ', '-').lower(),
            "text_channel": event_json["title"].replace(' ', '-').lower(),
            "website": event_json["url"], "weight": event_json["weight"],
            "description": event_json["description"], "start": unix_start,
            "end": unix_end, "duration": (((ctf_days + " days, ") + ctf_hours) + " hours"),
            "members": {}, "calculated?": False, "logo": event_json["logo"],
            "manual_solves": {}
        }

        # Update CTF DB for guild
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        server.update({'name': ctf_info["name"]}, {"$set": ctf_info}, upsert=True)

        # Discord server stuff
        whitelist = set(string.ascii_letters + string.digits + ' ' + '-')
        ctf_name = ctf_info["name"]
        await ctx.guild.create_text_channel(name=ctf_name, category=category)
        await ctx.guild.create_role(name=ctf_name, mentionable=True)
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

        # Get DB
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        mems = client[str(ctx.guild.name).replace(' ', '-')]['members']
        ctf = server.find_one({'name': str(ctx.message.channel)})

        # Add member to CTF DB along with alias in order for point processing
        members = ctf['members']
        members[str(user)] = {
            "alias": alias, "crypto": 0, "forensics": 0, "misc": 0, "osint": 0, "web exploitation": 0,
            "binary exploitation": 0, "reversing": 0, "tryhackme": 0, "cryptocurrency": 0, "network": 0, "mobile": 0
        }
        server.update({'name': str(ctx.message.channel)}, {"$unset": {'members': ""}}, upsert=True)
        server.update({'name': str(ctx.message.channel)}, {"$set": {'members': members}}, upsert=True)

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
        if self.creds and (str(guild_name).replace(' ', '-') + "." + str(channel)) in self.creds:
            name = self.creds[str(guild_name).replace(' ', '-') + "." + str(channel)]['user']
            replace_msg += "Replacing **{}**'s creds".format(name)

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
                        self.creds[str(guild_name).replace(' ', '-') + "." + str(channel)] = {
                            "token": username,
                            "site": site
                        }
                        message = "CTF credentials set. \n**Token:**\t ".format(username) + \
                              "` * * * * * * * * ` \n**Website:**\t` {} `".format(site)
                    else:
                        self.creds[str(guild_name).replace(' ', '-') + "." + str(channel)] = {
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
    async def pull_challs(self, ctx, url):
        fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
        try:
            if not self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))

            # Error message when CTF site is down and then returns
            if r.status_code == 404:
                await ctx.channel.send("CTF site is down. Try pulling challenges when it's up!")
                return

            if fingerprints[0] in r.text:
                user = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["user"]
                password = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["pass"]
                ctfd_challs = get_challenges_CTFd(ctx, url, user, password, s)
            elif fingerprints[1] in r.text:
                token = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["token"]
                ctfd_challs = get_challenges_rCTF(ctx, url, token, s)
            elif fingerprints[2] in r.text:
                # TODO - Implement CTFx functionality
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenges.")
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenges.")

            ctf_info = {'name': str(ctx.message.channel), 'challenges': ctfd_challs}
            server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
            server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
            await ctx.message.add_reaction("✅")
            return
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_ctf_channel()
    async def challs(self, ctx):
        ctf_challenge_list = []
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            actual_date = datetime.fromtimestamp(ctf['start']).strftime('%H:%M ET on %m/%d/%Y')
            await ctx.send("CTF has not started! Wait until {}".format(actual_date))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have chall info.")
            await CTF.pull_challs(self, ctx, self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["site"])
            #if not ctf['calculated?']: # we only want to calculate once
                #calculate(str(ctx.guild.name), str(ctx.message.channel))
        else:
            await CTF.pull_challs(self, ctx, self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["site"])


        # Print challenges to chat
        if 'challenges' in ctf.keys():
            ctf = server.find_one({'name': str(ctx.message.channel)}) # update local hash
            try:
                ctf_challenge_list = []
                message = ""
                message2 = ""
                print(ctf['challenges'].items())
                for k, v in ctf['challenges'].items():
                    if len(message) > 1500:
                        message2 = message
                        message = ""
                    message += "- {0}\n".format(k)
                    for chall in v:
                        message += "[{0}]({1}): ".format(chall['name'], chall['points'])
                        if chall['solved'] == True:
                            message += "Solved - {0}\n".format(chall['solver'])
                        else:
                            message += "Unsolved\n"
                    message += "\n"

                await ctx.send("```md\n{0}```".format(message))
                if message2:
                    await ctx.send("```md\n{0}```".format(message2))
            except:
                traceback.print_exc()

    @ctf.command()
    @in_ctf_channel()
    async def pull(self, ctx, chall):
        fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
        url = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["site"]
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            await ctx.send("CTF has not started! Wait until {}".format(ctf['start']))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have the challenge here somewhere...")

        # Get challenge info
        try:
            if not self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))
            if fingerprints[0] in r.text:
                user = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["user"]
                password = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["pass"]
                challenge_info = get_one_CTFd(ctx, url, user, password, s, chall)
            elif fingerprints[1] in r.text:
                raise InvalidProvider("rCTF functionality coming soon - cannot pull challenge.")
            elif fingerprints[2] in r.text:
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenge.")
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenge.")

            # Send info
            ti = "{} ({})".format(challenge_info['data']['name'], challenge_info['data']['value'])
            des = "{}".format(challenge_info['data']['description'])
            emb = discord.Embed(title=ti, description=des, colour=1752220)
            emb.add_field(name="Category", value=challenge_info['data']['category'], inline=True)
            emb.add_field(name="Solves", value=challenge_info['data']['solves'], inline=True)

            # Send attachments a.nd reaction
            files = []
            m = ""
            for i in range(len(challenge_info['data']['files'])):
                fn = challenge_info['data']['files'][i].split('?')[0].split('/')[-1]
                u = "{}{}".format(url, challenge_info['data']['files'][i])
                contents = s.get(u).text.encode()
                #contents = contents
                with open(fn, 'wb') as f:
                    f.write(contents)
                files.append(fn)
                m += fn + ', '

            if m == "": m = "N/A  "
            emb.add_field(name="Files", value=m[:-2], inline=True)
            await ctx.send(embed=emb)
            for j in files:
                await ctx.channel.send(file=discord.File(j))
                os.remove(j)
            await ctx.message.add_reaction("✅")
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_ctf_channel()
    async def solve(self, ctx, chall_name):
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        manual_solves = server.find_one({'name': str(ctx.message.channel)})['manual_solves']
        manual_solves[chall_name] = ctx.author.name

        ctf_info = {'name': str(ctx.message.channel), 'manual_solves': manual_solves}
        server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
        await ctx.channel.send("{} has solved `{}`".format(ctx.author.name, chall_name))

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(CTF(bot))
