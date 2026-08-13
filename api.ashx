<%@ WebHandler Language="C#" Class="ApiHandler" %>

using System;
using System.IO;
using System.Web;
using System.Text;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Net.Mail;
using System.Net;

/// <summary>
/// Cyber Security Training — Server API
/// 
/// Place this file alongside cyber_training_v3.html on IIS.
/// Requires a writable "data" subfolder (IIS_IUSRS needs write permission).
/// 
/// Endpoints:
///   GET  api.ashx?action=getall    → Returns all profiles as JSON
///   POST api.ashx?action=save      → Saves/updates a single profile
///   GET  api.ashx?action=export    → Downloads all data as JSON file
///   POST api.ashx?action=import    → Merges imported profiles
///   POST api.ashx?action=clear     → Clears all data
/// </summary>
public class ApiHandler : IHttpHandler
{
    private static readonly object _lock = new object();

    // ══ SMTP CONFIGURATION — Edit these to enable email from the dashboard ══
    // Set SMTP_ENABLED to true once you've configured your SMTP settings.
    private const bool SMTP_ENABLED = false;
    private const string SMTP_SERVER = "smtp.yourdomain.com";
    private const int SMTP_PORT = 587;
    private const string SMTP_USER = "reports@yourdomain.com";
    private const string SMTP_PASS = "your_smtp_password";
    private const string SMTP_FROM = "reports@yourdomain.com";
    private const bool SMTP_SSL = true;
    private const string TRAINING_URL = "http://yourserver/training/";

    public bool IsReusable { get { return true; } }

    public void ProcessRequest(HttpContext context)
    {
        var req = context.Request;
        var res = context.Response;

        res.ContentType = "application/json";
        res.ContentEncoding = Encoding.UTF8;
        res.AddHeader("Access-Control-Allow-Origin", "*");
        res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.AddHeader("Access-Control-Allow-Headers", "Content-Type");
        res.AddHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        res.AddHeader("Pragma", "no-cache");
        res.AddHeader("Expires", "0");

        // Handle CORS preflight
        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 200;
            return;
        }

        string dataDir = Path.Combine(Path.GetDirectoryName(context.Request.PhysicalPath), "data");
        string dataFile = Path.Combine(dataDir, "profiles.json");

        // Ensure data directory exists
        if (!Directory.Exists(dataDir))
            Directory.CreateDirectory(dataDir);

        string action = (req.QueryString["action"] ?? "").ToLower();

        try
        {
            switch (action)
            {
                case "getall":
                    res.Write(ReadProfiles(dataFile));
                    break;

                case "save":
                    RequirePost(req);
                    HandleSave(req, res, dataFile);
                    break;

                case "export":
                    HandleExport(res, dataFile);
                    break;

                case "import":
                    RequirePost(req);
                    HandleImport(req, res, dataFile);
                    break;

                case "clear":
                    RequirePost(req);
                    lock (_lock) { File.WriteAllText(dataFile, "{}", Encoding.UTF8); }
                    res.Write("{\"success\":true,\"message\":\"All data cleared\"}");
                    break;

                case "archive":
                    RequirePost(req);
                    HandleArchive(req, res, dataFile, true);
                    break;

                case "unarchive":
                    RequirePost(req);
                    HandleArchive(req, res, dataFile, false);
                    break;

                case "delete":
                    RequirePost(req);
                    HandleDelete(req, res, dataFile);
                    break;

                case "enroll":
                    RequirePost(req);
                    HandleEnroll(req, res, dataFile);
                    break;

                case "email":
                    RequirePost(req);
                    HandleEmail(req, res);
                    break;

                case "check":
                {
                    string checkName = (req.QueryString["name"] ?? "").ToLower().Trim();
                    string checkEmail = (req.QueryString["email"] ?? "").ToLower().Trim();
                    
                    string allJson = ReadProfiles(dataFile);
                    var checkSerializer = new JavaScriptSerializer();
                    checkSerializer.MaxJsonLength = int.MaxValue;
                    var allProfiles = checkSerializer.Deserialize<Dictionary<string, object>>(allJson) ?? new Dictionary<string, object>();
                    
                    Dictionary<string, object> foundProf = null;
                    string foundKey = "";

                    if (!string.IsNullOrEmpty(checkEmail))
                    {
                        // Search by email across all profiles
                        foreach (var kvp in allProfiles)
                        {
                            var p = kvp.Value as Dictionary<string, object>;
                            if (p != null && p.ContainsKey("email"))
                            {
                                string pEmail = (p["email"] ?? "").ToString().ToLower().Trim();
                                if (pEmail == checkEmail)
                                {
                                    foundProf = p;
                                    foundKey = kvp.Key;
                                    break;
                                }
                            }
                        }
                    }
                    else if (!string.IsNullOrEmpty(checkName))
                    {
                        // Search by name (original behavior)
                        if (allProfiles.ContainsKey(checkName))
                        {
                            foundProf = allProfiles[checkName] as Dictionary<string, object>;
                            foundKey = checkName;
                        }
                    }
                    else
                    {
                        res.Write("{\"enrolled\":false,\"error\":\"No name or email provided\"}");
                        break;
                    }

                    if (foundProf != null)
                    {
                        bool isArchived = foundProf.ContainsKey("archived") && (bool)foundProf["archived"] == true;
                        if (isArchived)
                        {
                            res.Write("{\"enrolled\":false,\"archived\":true,\"name\":\"" + EscapeJson(foundKey) + "\"}");
                        }
                        else
                        {
                            string profJson = checkSerializer.Serialize(foundProf);
                            res.Write("{\"enrolled\":true,\"name\":\"" + EscapeJson(foundKey) + "\",\"profile\":" + profJson + "}");
                        }
                    }
                    else
                    {
                        res.Write("{\"enrolled\":false,\"name\":\"" + EscapeJson(!string.IsNullOrEmpty(checkEmail) ? checkEmail : checkName) + "\"}");
                    }
                    break;
                }

                default:
                    res.StatusCode = 400;
                    res.Write("{\"error\":\"Unknown action. Use: getall, save, export, import, clear\"}");
                    break;
            }
        }
        catch (Exception ex)
        {
            res.StatusCode = 500;
            res.Write("{\"error\":\"" + EscapeJson(ex.Message) + "\"}");
        }
    }

    // ── Read all profiles from disk ──
    private string ReadProfiles(string path)
    {
        lock (_lock)
        {
            if (File.Exists(path))
                return File.ReadAllText(path, Encoding.UTF8);
            return "{}";
        }
    }

    // ── Write all profiles to disk ──
    private void WriteProfiles(string path, string json)
    {
        lock (_lock)
        {
            File.WriteAllText(path, json, Encoding.UTF8);
        }
    }

    // ── Require POST method ──
    private void RequirePost(HttpRequest req)
    {
        if (req.HttpMethod != "POST")
            throw new Exception("POST method required");
    }

    // ── Read POST body ──
    private string ReadBody(HttpRequest req)
    {
        using (var reader = new StreamReader(req.InputStream, Encoding.UTF8))
        {
            return reader.ReadToEnd();
        }
    }

    // ── SAVE: merge a single profile ──
    private void HandleSave(HttpRequest req, HttpResponse res, string dataFile)
    {
        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;

        var incoming = serializer.Deserialize<Dictionary<string, object>>(body);
        if (incoming == null || !incoming.ContainsKey("key") || !incoming.ContainsKey("profile"))
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"Invalid data. Expected {key, profile}\"}");
            return;
        }

        string key = incoming["key"].ToString().ToLower();
        var profile = incoming["profile"] as Dictionary<string, object>;
        if (profile == null)
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"Invalid profile data\"}");
            return;
        }

        lock (_lock)
        {
            string existing = ReadProfilesUnsafe(dataFile);
            var all = serializer.Deserialize<Dictionary<string, object>>(existing)
                      ?? new Dictionary<string, object>();

            if (!all.ContainsKey(key))
            {
                all[key] = profile;
            }
            else
            {
                var current = all[key] as Dictionary<string, object>;
                if (current == null)
                {
                    all[key] = profile;
                }
                else
                {
                    // Merge: update atk/def if incoming score is >= existing
                    MergeRole(current, profile, "atk");
                    MergeRole(current, profile, "def");
                    if (profile.ContainsKey("name"))
                        current["name"] = profile["name"];
                    if (profile.ContainsKey("lastActive"))
                        current["lastActive"] = profile["lastActive"];
                    // Preserve enrollment fields that the training app doesn't send
                    // (property, email, enrolled, dueBy are set by admin, not overwritten by training sync)
                    all[key] = current;
                }
            }

            File.WriteAllText(dataFile, serializer.Serialize(all), Encoding.UTF8);
        }

        res.Write("{\"success\":true}");
    }

    // ── Merge a single role (atk or def) — last write wins ──
    private void MergeRole(Dictionary<string, object> current, Dictionary<string, object> incoming, string role)
    {
        if (!incoming.ContainsKey(role) || incoming[role] == null) return;

        var inRole = incoming[role] as Dictionary<string, object>;
        if (inRole == null) return;

        // Always accept the incoming data — the training app pulls fresh
        // data from the server before each session, so the client is authoritative.
        current[role] = inRole;
    }

    private int GetIntValue(Dictionary<string, object> dict, string key)
    {
        if (dict.ContainsKey(key) && dict[key] != null)
        {
            int val;
            if (int.TryParse(dict[key].ToString(), out val)) return val;
        }
        return 0;
    }

    private long GetLongValue(Dictionary<string, object> dict, string key)
    {
        if (dict.ContainsKey(key) && dict[key] != null)
        {
            long val;
            if (long.TryParse(dict[key].ToString(), out val)) return val;
        }
        return 0;
    }

    // ── EXPORT: download as JSON file ──
    private void HandleExport(HttpResponse res, string dataFile)
    {
        res.ContentType = "application/octet-stream";
        string date = DateTime.Now.ToString("yyyy-MM-dd");
        res.AddHeader("Content-Disposition", "attachment; filename=cyber_training_export_" + date + ".json");

        string profiles = ReadProfiles(dataFile);
        string export = "{\"exportDate\":\"" + DateTime.Now.ToString("o") + "\","
                       + "\"source\":\"" + EscapeJson(Environment.MachineName) + "\","
                       + "\"profiles\":" + profiles + "}";
        res.Write(export);
    }

    // ── IMPORT: bulk merge profiles ──
    private void HandleImport(HttpRequest req, HttpResponse res, string dataFile)
    {
        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;

        var importData = serializer.Deserialize<Dictionary<string, object>>(body);
        if (importData == null)
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"Invalid JSON\"}");
            return;
        }

        // Support both {profiles:{...}} wrapper and flat {name:{...}} format
        Dictionary<string, object> profiles;
        if (importData.ContainsKey("profiles") && importData["profiles"] is Dictionary<string, object>)
            profiles = importData["profiles"] as Dictionary<string, object>;
        else
            profiles = importData;

        int added = 0, updated = 0;

        lock (_lock)
        {
            string existing = ReadProfilesUnsafe(dataFile);
            var all = serializer.Deserialize<Dictionary<string, object>>(existing)
                      ?? new Dictionary<string, object>();

            foreach (var kvp in profiles)
            {
                string key = kvp.Key.ToLower();
                var prof = kvp.Value as Dictionary<string, object>;
                if (prof == null) continue;

                if (!all.ContainsKey(key))
                {
                    all[key] = prof;
                    added++;
                }
                else
                {
                    var cur = all[key] as Dictionary<string, object>;
                    if (cur != null)
                    {
                        MergeRole(cur, prof, "atk");
                        MergeRole(cur, prof, "def");
                        all[key] = cur;
                        updated++;
                    }
                }
            }

            File.WriteAllText(dataFile, serializer.Serialize(all), Encoding.UTF8);
        }

        res.Write("{\"success\":true,\"added\":" + added + ",\"updated\":" + updated + "}");
    }

    // ── Read without lock (caller must hold lock) ──
    private string ReadProfilesUnsafe(string path)
    {
        if (File.Exists(path))
            return File.ReadAllText(path, Encoding.UTF8);
        return "{}";
    }

    // ── ENROLL: bulk create empty profiles for staff ──
    private void HandleEnroll(HttpRequest req, HttpResponse res, string dataFile)
    {
        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;

        var data = serializer.Deserialize<Dictionary<string, object>>(body);
        if (data == null || !data.ContainsKey("staff"))
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"Expected {staff:[...]}\"}");
            return;
        }

        var staffArray = data["staff"] as object[];
        if (staffArray == null)
        {
            // Try ArrayList
            var staffList = data["staff"] as System.Collections.ArrayList;
            if (staffList != null) staffArray = staffList.ToArray();
        }
        if (staffArray == null)
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"staff must be an array\"}");
            return;
        }

        int added = 0, updated = 0, skipped = 0;
        string now = DateTime.Now.ToString("o");

        lock (_lock)
        {
            string existing = ReadProfilesUnsafe(dataFile);
            var all = serializer.Deserialize<Dictionary<string, object>>(existing)
                      ?? new Dictionary<string, object>();

            foreach (var item in staffArray)
            {
                var person = item as Dictionary<string, object>;
                if (person == null || !person.ContainsKey("name")) { skipped++; continue; }

                string name = person["name"].ToString().Trim();
                string key = name.ToLower();
                if (string.IsNullOrEmpty(key)) { skipped++; continue; }

                string propVal = person.ContainsKey("property") ? (person["property"] ?? "").ToString() : "";
                string emailVal = person.ContainsKey("email") ? (person["email"] ?? "").ToString() : "";
                string dueVal = person.ContainsKey("dueBy") ? (person["dueBy"] ?? "").ToString() : "";

                if (all.ContainsKey(key))
                {
                    // Update enrollment fields without overwriting training data
                    var current = all[key] as Dictionary<string, object>;
                    if (current != null)
                    {
                        if (!string.IsNullOrEmpty(propVal)) current["property"] = propVal;
                        if (!string.IsNullOrEmpty(emailVal)) current["email"] = emailVal;
                        if (!string.IsNullOrEmpty(dueVal)) current["dueBy"] = dueVal;
                        all[key] = current;
                        updated++;
                    }
                }
                else
                {
                    var newProfile = new Dictionary<string, object>();
                    newProfile["name"] = name;
                    newProfile["property"] = propVal;
                    newProfile["email"] = emailVal;
                    newProfile["enrolled"] = now;
                    if (!string.IsNullOrEmpty(dueVal)) newProfile["dueBy"] = dueVal;
                    all[key] = newProfile;
                    added++;
                }
            }

            File.WriteAllText(dataFile, serializer.Serialize(all), Encoding.UTF8);
        }

        res.Write("{\"success\":true,\"added\":" + added + ",\"updated\":" + updated + ",\"skipped\":" + skipped + "}");
    }

    // ── EMAIL: send welcome or reminder email ──
    private void HandleEmail(HttpRequest req, HttpResponse res)
    {
        if (!SMTP_ENABLED)
        {
            res.Write("{\"error\":\"Email is not configured. Edit SMTP settings in api.ashx and set SMTP_ENABLED to true.\"}");
            return;
        }

        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        var data = serializer.Deserialize<Dictionary<string, object>>(body);

        if (data == null || !data.ContainsKey("to") || !data.ContainsKey("type"))
        {
            res.Write("{\"error\":\"Missing required fields: to, type\"}");
            return;
        }

        string toAddr = data["to"].ToString();
        string emailType = data["type"].ToString();
        string personName = data.ContainsKey("name") ? data["name"].ToString() : "";
        string dueBy = data.ContainsKey("dueBy") ? data["dueBy"].ToString() : "";
        string incomplete = data.ContainsKey("incomplete") ? data["incomplete"].ToString() : "both training stages";

        string subject = "";
        string htmlBody = "";

        string headerBlock = @"<!DOCTYPE html><html><body style=""font-family:Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;padding:20px;color:#333"">
<div style=""background:#1a1a2e;padding:24px;border-radius:8px;text-align:center;margin-bottom:20px"">
<h1 style=""color:#00ff41;font-size:18px;letter-spacing:2px;margin:0"">CYBER SECURITY TRAINING</h1>";

        string buttonBlock = @"<div style=""text-align:center;margin:24px 0"">
<a href=""" + TRAINING_URL + @""" style=""display:inline-block;padding:12px 28px;background:#1a1a2e;color:#00ff41;text-decoration:none;border-radius:4px;font-weight:700;letter-spacing:1px"">";

        string footerBlock = @"<p style=""font-size:13px;color:#666"">If you have questions, please contact your administrator.</p></body></html>";

        if (emailType == "welcome")
        {
            subject = "Welcome to Cyber Security Training";
            string dueNote = !string.IsNullOrEmpty(dueBy)
                ? @"<p style=""font-size:14px;color:#666"">Please complete by: <strong>" + dueBy + "</strong></p>"
                : "";
            htmlBody = headerBlock
                + @"<p style=""color:#8892a4;font-size:12px;margin:4px 0 0"">You have been enrolled</p></div>"
                + "<p>Hi <strong>" + personName + "</strong>,</p>"
                + "<p>You have been enrolled in our cyber security awareness training program. "
                + "This interactive training covers personal security fundamentals and how to recognize modern phishing and deepfake threats.</p>"
                + dueNote
                + "<p>The training is self-paced and takes approximately 30-45 minutes per stage.</p>"
                + buttonBlock + "START TRAINING</a></div>"
                + footerBlock;
        }
        else if (emailType == "reminder")
        {
            subject = "Reminder: Complete Your Cyber Security Training";
            string dueNote = "";
            if (!string.IsNullOrEmpty(dueBy))
            {
                DateTime dueDate;
                if (DateTime.TryParse(dueBy, out dueDate))
                {
                    int daysLeft = (dueDate - DateTime.Now).Days;
                    if (daysLeft < 0)
                        dueNote = @"<p style=""color:#dc2626;font-weight:700"">Your training deadline was " + dueBy + ". Please complete it as soon as possible.</p>";
                    else if (daysLeft <= 7)
                        dueNote = @"<p style=""color:#d97706;font-weight:700"">Your training is due by " + dueBy + " (" + daysLeft + " day" + (daysLeft != 1 ? "s" : "") + " remaining).</p>";
                    else
                        dueNote = @"<p style=""color:#666"">Training due by: " + dueBy + "</p>";
                }
            }
            htmlBody = headerBlock
                + @"<p style=""color:#8892a4;font-size:12px;margin:4px 0 0"">Training Reminder</p></div>"
                + "<p>Hi <strong>" + personName + "</strong>,</p>"
                + "<p>This is a friendly reminder that you have incomplete cyber security awareness training. "
                + "You still need to complete: <strong>" + incomplete + "</strong>.</p>"
                + dueNote
                + buttonBlock + "CONTINUE TRAINING</a></div>"
                + footerBlock;
        }
        else
        {
            res.Write("{\"error\":\"Unknown email type. Use: welcome, reminder\"}");
            return;
        }

        try
        {
            var smtp = new SmtpClient(SMTP_SERVER, SMTP_PORT);
            smtp.EnableSsl = SMTP_SSL;
            smtp.Credentials = new NetworkCredential(SMTP_USER, SMTP_PASS);

            var msg = new MailMessage();
            msg.From = new MailAddress(SMTP_FROM);
            msg.To.Add(toAddr);
            msg.Subject = subject;
            msg.IsBodyHtml = true;
            msg.Body = htmlBody;

            smtp.Send(msg);
            res.Write("{\"success\":true,\"sent\":\"" + EscapeJson(toAddr) + "\"}");
        }
        catch (Exception ex)
        {
            res.Write("{\"error\":\"Email failed: " + EscapeJson(ex.Message) + "\"}");
        }
    }

    // ── ARCHIVE: mark a profile as archived (not deleted) ──
    private void HandleArchive(HttpRequest req, HttpResponse res, string dataFile, bool doArchive)
    {
        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        var data = serializer.Deserialize<Dictionary<string, object>>(body);

        if (data == null || !data.ContainsKey("key"))
        {
            res.Write("{\"error\":\"Missing key\"}");
            return;
        }

        string key = data["key"].ToString().ToLower();

        lock (_lock)
        {
            string existing = ReadProfilesUnsafe(dataFile);
            var all = serializer.Deserialize<Dictionary<string, object>>(existing)
                      ?? new Dictionary<string, object>();

            if (all.ContainsKey(key))
            {
                var profile = all[key] as Dictionary<string, object>;
                if (profile != null)
                {
                    if (doArchive)
                    {
                        profile["archived"] = true;
                        profile["archivedDate"] = DateTime.Now.ToString("o");
                    }
                    else
                    {
                        profile.Remove("archived");
                        profile.Remove("archivedDate");
                    }
                    all[key] = profile;
                    File.WriteAllText(dataFile, serializer.Serialize(all), Encoding.UTF8);
                    res.Write("{\"success\":true,\"key\":\"" + EscapeJson(key) + "\",\"archived\":" + (doArchive ? "true" : "false") + "}");
                }
                else
                {
                    res.Write("{\"success\":true,\"message\":\"Key not found\"}");
                }
            }
            else
            {
                res.Write("{\"success\":true,\"message\":\"Key not found\"}");
            }
        }
    }

    // ── DELETE: remove a single profile by key ──
    private void HandleDelete(HttpRequest req, HttpResponse res, string dataFile)
    {
        string body = ReadBody(req);
        var serializer = new JavaScriptSerializer();
        var data = serializer.Deserialize<Dictionary<string, object>>(body);
        
        if (data == null || !data.ContainsKey("key"))
        {
            res.StatusCode = 400;
            res.Write("{\"error\":\"Missing key\"}");
            return;
        }

        string key = data["key"].ToString().ToLower();

        lock (_lock)
        {
            string existing = ReadProfilesUnsafe(dataFile);
            var all = serializer.Deserialize<Dictionary<string, object>>(existing)
                      ?? new Dictionary<string, object>();

            if (all.ContainsKey(key))
            {
                all.Remove(key);
                File.WriteAllText(dataFile, serializer.Serialize(all), Encoding.UTF8);
                res.Write("{\"success\":true,\"deleted\":\"" + EscapeJson(key) + "\"}");
            }
            else
            {
                res.Write("{\"success\":true,\"message\":\"Key not found, nothing to delete\"}");
            }
        }
    }

    // ── Escape string for JSON output ──
    private string EscapeJson(string s)
    {
        if (s == null) return "";
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "");
    }
}
