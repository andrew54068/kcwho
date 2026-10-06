"""Real requester regression fixtures follow captured securityd events."""
import json, os, runpy, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

KC=runpy.run_path(str(Path(__file__).resolve().parents[1]/"kcwho"))
PATHS={10:KC["GENUINE"]["SecurityAgent"],20:"/usr/bin/security",30:KC["ICLOUD_HELPER"],40:"/private/tmp/kcwho-login-test",900:"/usr/sbin/securityd"}
STAMP="2026-10-05 14:04:16.449445+0800"
def event(message,category="kcacl",thread=1,path="/usr/sbin/securityd",boot="BOOT1"):
    return dict(processID=900,processImagePath=path,threadID=thread,timestamp=STAMP,
                eventMessage=message,category=category,bootUUID=boot,eventType="logEvent")
def prompt(pid=20,pointer="0x123",thread=1):
    return [event("Keychain query for process %d (UID %d)"%(pid,os.getuid()),thread=thread),
            event("displaying keychain prompt for %s(%d); ACL: DO-NOT-EXPORT"%(PATHS[pid],pid),thread=thread),
            event("new SecurityAgentXPCQuery(%s)"%pointer,"SecurityAgentXPCQuery",thread)]
OLD=dict(processID=30,processImagePath=PATHS[30],threadID=7,timestamp=STAMP,
         eventMessage="AOSKit INFO: (com.apple.remindd/3740) ACCT LOOKUP: No appleAccountInfo found, recording lookup attempt (user=SECRET-ACCOUNT)")

class RequestOwnership(unittest.TestCase):
    def report(self,records,popup=True,log_error=False,infos=None,client_args=None,helper_args=None):
        def run(*args,**kwargs):
            out=""
            if args[0]=="/usr/bin/osascript":out="10\tSecurityAgent\n" if popup else "99\tFinder\n"
            elif args[0]=="/usr/sbin/sysctl":out="BOOT1\n"
            elif args[:3]==("/bin/ps","-axo","pid=,ppid="):out="10 1\n20 1\n30 1\n40 1\n"
            elif args[:3]==("/bin/ps","-axo","pid=,lstart="):out="10 Mon Oct 5 14:04:16 2026\n20 Mon Oct 5 14:03:00 2026\n30 Mon Oct 5 14:03:00 2026\n40 Mon Oct 5 14:03:00 2026\n"
            elif args[0]=="/bin/launchctl":out="PID\tStatus\tLabel\n20\t0\tknown-test\n"
            elif args[0]=="/usr/bin/log":return SimpleNamespace(stdout=json.dumps(records),stderr="",returncode=1 if log_error else 0)
            return SimpleNamespace(stdout=out,stderr="",returncode=0)
        def identity(pid):
            if infos and pid in infos:return infos[pid]
            return dict(pid=pid,path=PATHS[pid],started=1791180180.0,apple_signed=pid in (20,30),
                        signing="Apple" if pid in (20,30) else "Ad-hoc")
        env=dict(run=run,all_pids=lambda:list(PATHS),exe=lambda pid:PATHS.get(pid,"?"),
                 responsible=lambda pid:pid,process_info=identity,
                 argv=lambda pid:(client_args or ["security","find-generic-password","-s","dummy"]) if pid==20 else (helper_args if pid==30 and helper_args else [PATHS.get(pid,"?")]))
        with patch.dict(KC["collect"].__globals__,env):return KC["collect"]()
    def test_known_request_uses_native_pid_not_old_helper(self):
        r=self.report([OLD]+prompt())
        self.assertEqual([w.get("requester") for w in r["waiting"]],["security"])
        self.assertEqual(r["waiting"][0]["pid"],20)
        self.assertNotIn("DO-NOT-EXPORT",json.dumps(r))
    def test_unknown_executable_needs_no_name_whitelist(self):
        r=self.report(prompt(40))
        self.assertEqual([w.get("requester") for w in r["waiting"]],["kcwho-login-test"])
        self.assertEqual(r["waiting"][0]["signing"],"Ad-hoc")
    def test_admin_with_stale_helper_lookup_is_not_keychain(self):
        r=self.report([OLD])
        self.assertEqual(r["waiting"],[])
        self.assertEqual(r.get("kind"),"none")
    def test_query_destruction_removes_request(self):
        self.assertEqual(self.report(prompt()+[event("SecurityAgentXPCQuery(0x123) dying","SecurityAgentXPCQuery")])["waiting"],[])
    def test_multiple_native_requests_are_not_collapsed(self):
        self.assertEqual({w.get("pid") for w in self.report(prompt()+prompt(40,"0x456",2))["waiting"]},{20,40})
    def test_wrong_boot_and_spoofed_source_are_rejected(self):
        old=prompt();spoof=prompt()
        for r in old:r["bootUUID"]="OLD"
        for r in spoof:r["processImagePath"]="/tmp/securityd"
        self.assertEqual(self.report(old+spoof)["waiting"],[])
    def test_pid_reuse_is_not_attributed_to_new_process(self):
        self.assertEqual(self.report(prompt(),infos={20:dict(pid=20,path="/tmp/other",started=1791180500.0)})["waiting"],[])
    def test_missing_caller_details_are_unknown(self):
        r=self.report([event("new SecurityAgentXPCQuery(0x999)","SecurityAgentXPCQuery")])
        self.assertEqual(r["waiting"],[])
        self.assertEqual(r.get("kind"),"unknown")
    def test_missing_logs_never_promote_helper(self):
        r=self.report([OLD],log_error=True)
        self.assertEqual(r["waiting"],[])
        self.assertEqual(r.get("kind"),"unknown")
    def test_no_dialog_has_no_requester(self):
        self.assertEqual(self.report(prompt(),popup=False)["waiting"],[])
    def test_helper_upstream_is_not_claimed_as_direct_requester(self):
        r=self.report([OLD]+prompt(30))
        self.assertEqual([w.get("requester") for w in r["waiting"]],["iCloud Helper"])
        self.assertNotIn("SECRET-ACCOUNT",json.dumps(r))
    def test_security_password_is_not_exported(self):
        self.assertNotIn("TEST-SECRET",json.dumps(self.report([],client_args=["security","unlock-keychain","-p","TEST-SECRET"])))
    def test_helper_command_line_secret_is_not_exported(self):
        r=self.report([],helper_args=[PATHS[30],"--token","dummy-sensitive-argument"])
        self.assertNotIn("dummy-sensitive-argument",json.dumps(r))
    def test_missing_start_or_lost_events_cannot_identify_caller(self):
        r=self.report(prompt(),infos={20:dict(pid=20,path=PATHS[20],started=None)})
        self.assertEqual(r["waiting"],[])
        loss=event("lost");loss["eventType"]="lossEvent"
        self.assertEqual(self.report(prompt()+[loss])["waiting"],[])
    def test_query_pointer_reuse_is_a_new_request(self):
        records=prompt()+[event("SecurityAgentXPCQuery(0x123) dying","SecurityAgentXPCQuery")]+prompt(40)
        self.assertEqual({w["pid"] for w in self.report(records)["waiting"]},{40})
    def test_old_daemon_instance_cannot_leave_active_requests(self):
        rows=prompt()
        for row in rows:row["processID"]=901
        self.assertEqual(self.report(rows)["waiting"],[])
    def test_mismatched_display_cannot_reuse_previous_context(self):
        rows=prompt()
        rows.insert(2,event("displaying keychain prompt for %s(40); ACL:"%PATHS[40]))
        self.assertEqual(self.report(rows)["waiting"],[])
    def test_pointer_reused_by_other_user_clears_previous_request(self):
        other=prompt(40)
        other[0]["eventMessage"]="Keychain query for process 40 (UID %d)"%(os.getuid()+1)
        self.assertEqual(self.report(prompt()+other)["waiting"],[])

if __name__=="__main__":unittest.main()
