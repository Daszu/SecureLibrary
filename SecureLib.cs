using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Security.Permissions;
using System.Threading;
using System.Data.SqlClient;

namespace Secure_Library
{
    public interface IUserCtx
    {
        string UName { get; set; }
        string FName { get; set; }
        string LName { get; set; }
        string Pass { get; set; }
        bool HasPermission(string roleName);
        bool HasGroup(string groupName);
        List<string> GetAllPermissions();
        List<string> GetAllGroups();
    }

    class UserCtx : IUserCtx
    {
        private string uname, fname, lname, psswd;
        private List<string> Permissions;
        private List<string> Groups;

        public UserCtx(string un)
        {
            uname = un;
            Permissions = new List<string>();
            Groups = new List<string>();
        }

        public string UName
        {
            get { return uname; }
            set { uname = value; }
        }

        public string FName
        {
            get { return fname; }
            set { fname = value; }
        }

        public string LName
        {
            get { return lname; }
            set { lname = value; }
        }

        public string Pass
        {
            get { return psswd; }
            set { psswd = value; }
        }

        public void AddPermissions(string p)
        {
            Permissions.Add(p);
        }

        public void AddGroup(string g)
        {
            Groups.Add(g);
        }

        public bool HasPermission(string p)
        {
            return Permissions.Contains(p);
        }

        public bool HasGroup(string g)
        {
            return Groups.Contains(g);
        }

        public List<string> GetAllPermissions()
        {
            return Permissions;
        }

        public List<string> GetAllGroups()
        {
            return Groups;
        }
    }

    public static class Roles
    {
        public const string CREATE_USER         = "createUser";
        public const string DELETE_USER         = "deleteUser";
        public const string CREATE_POST         = "createPost";
        public const string MODIFY_POST         = "modifyPost";
        public const string DELETE_POST         = "deletePost";
        public const string GROUP_PERMISSION    = "groupPermission";
        public const string USER_PERMISSION     = "userPermission";
        public const string CREATE_GROUP        = "createGroup";
        public const string USER_GROUP          = "userGroup";
        public const string DELETE_GROUP        = "deleteGroup";
    }

    public class SecureLib
    {
        public static DataClasses1DataContext myConnection;
        public static GenericIdentity gi;
        public static GenericPrincipal gp;
        private User person = null;

        public SecureLib()
        {
            myConnection = new DataClasses1DataContext();
        }

        public bool login(string name, string pass, out IUserCtx uCt)
        {
            uCt = null;

            try
            {
                person = myConnection.Users.Single(u => u.Name == name && u.Pass == pass);
            }
            catch(InvalidOperationException exc)
            {
                return false;
            }
            catch (SqlException sqle)
            {
                throw sqle;
            }
            finally
            {
                if (person != null)
                {
                    gi = new GenericIdentity(person.Name);
                    UserCtx uCtx = new UserCtx(person.Name);
                    var grpSet = from gu in myConnection.GroupUsers join grp in myConnection.Groups on gu.GroupId equals grp.GroupID where gu.UserID == person.UserID select grp;
                    var grpPermSet = from gu in myConnection.GroupUsers join grp in myConnection.GroupPermissions on gu.GroupId equals grp.GroupID join p in myConnection.Permissions on grp.PermID equals p.PermID where gu.UserID == person.UserID select p;
                    var usrPermSet = from up in myConnection.UserPermissions join pe in myConnection.Permissions on up.PermID equals pe.PermID where up.UserID == person.UserID select pe;
                    var permSet = grpPermSet.Union(usrPermSet);

                    foreach (Group g in grpSet)
                    {
                        uCtx.AddGroup(g.Name);
                    }

                    foreach (Permission p in permSet)
                    {
                        uCtx.AddPermissions(p.Name);
                    }

                    uCtx.FName = person.FName;
                    uCtx.LName = person.LName;
                    uCtx.Pass = person.Pass;

                    uCt = uCtx;

                    gp = new GenericPrincipal(gi, uCtx.GetAllPermissions().ToArray());

                    foreach (string sp in uCtx.GetAllPermissions().ToArray())
                    {
                        Console.WriteLine(sp);
                    }
                }
            }

            return true;
        }

    }
}
