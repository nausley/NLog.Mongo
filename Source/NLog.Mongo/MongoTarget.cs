using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Driver;
using NLog.Common;
using NLog.Config;
using NLog.Targets;

namespace NLog.Mongo
{
    /// <summary>
    /// NLog message target for MongoDB.
    /// </summary>
    [Target("Mongo")]
    public class MongoTarget : Target
    {
        
        private static readonly ConcurrentDictionary<string, IMongoCollection<BsonDocument>> CollectionCache = new ConcurrentDictionary<string, IMongoCollection<BsonDocument>>();
        private static IMongoDatabase _mongoDatabase;

        /// <summary>
        /// Initializes a new instance of the <see cref="MongoTarget"/> class.
        /// </summary>
        public MongoTarget()
        {
            Fields = new List<MongoField>();
            Properties = new List<MongoField>();
            IncludeDefaults = true;
            DatabaseName = "NLog";
            UseAuth = false;
            UseSsl = false;
            UseX509 = false;
            ReplicaSetName = "";
        }

        /// <summary>
        /// Gets the fields collection.
        /// </summary>
        /// <value>
        /// The fields.
        /// </value>
        [ArrayParameter(typeof(MongoField), "field")]
        public IList<MongoField> Fields { get; }

        /// <summary>
        /// Gets the properties collection.
        /// </summary>
        /// <value>
        /// The properties.
        /// </value>
        [ArrayParameter(typeof(MongoField), "property")]
        public IList<MongoField> Properties { get; }


        #region Properties

        /// <summary>
        /// Gets or sets the connection string name string.
        /// </summary>
        /// <value>
        /// The connection name string.
        /// </value>
        public string ConnectionString { get; set; }

        /// <summary>
        /// Gets or sets the name of the connection.
        /// </summary>
        /// <value>
        /// The name of the connection.
        /// </value>
        public string ConnectionName { get; set; }

        /// <summary>
        /// Gets or sets the database name string.
        /// </summary>
        public string DatabaseName { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to use the default document format.
        /// </summary>
        /// <value>
        ///   <c>true</c> to use the default document format; otherwise, <c>false</c>.
        /// </value>
        public bool IncludeDefaults { get; set; }

        /// <summary>
        /// Gets or sets the name of the collection.
        /// </summary>
        /// <value>
        /// The name of the collection.
        /// </value>
        public string CollectionName { get; set; }

        /// <summary>
        /// Gets or sets the size in bytes of the capped collection.
        /// </summary>
        /// <value>
        /// The size of the capped collection.
        /// </value>
        public long? CappedCollectionSize { get; set; }

        /// <summary>
        /// Gets or sets the capped collection max items.
        /// </summary>
        /// <value>
        /// The capped collection max items.
        /// </value>
        public long? CappedCollectionMaxItems { get; set; }

        /// <summary>
        /// Gets or Sets ReplicaSetName
        /// </summary>
        public string ReplicaSetName { get; set; }
        
        /// <summary>
        /// Use Mongo Authentication to access database (system level)
        /// </summary>
        public bool UseAuth { get; set; }
        
        /// <summary>
        /// Use SSL Connection
        /// </summary>
        public bool UseSsl { get; set; }
        
        /// <summary>
        /// Use SSL x509 Authentication Certifications
        /// </summary>
        public bool UseX509 { get; set; }
        
        /// <summary>
        /// Used for basic user/password Authentication
        /// </summary>
        public string AuthDatabase { get; set; }
        
        /// <summary>
        /// Get or Set UserName, also used for DN when used with UseX509 Authentication
        /// </summary>
        public string UserName { get; set; }
        
        /// <summary>
        /// Set User Password
        /// </summary>
        public string UserPassword { private get; set; }
        
        /// <summary>
        /// Set ClientCertPfx User Certification for SSL and X509
        /// </summary>
        public string ClientCertPfx { private get; set; }

        /// <summary>
        /// Set ClientCertPassword (if needed)
        /// </summary>
        public string ClientCertPassword { private get; set; }

        #endregion

        /// <summary>
        /// Initializes the target. Can be used by inheriting classes
        /// to initialize logging.
        /// </summary>
        /// <exception cref="NLog.NLogConfigurationException">Can not resolve MongoDB ConnectionString. Please make sure the ConnectionString property is set.</exception>
        protected override void InitializeTarget()
        {
            string replicaSet;
            base.InitializeTarget();
//            if (!string.IsNullOrEmpty(ConnectionName))
//                ConnectionString = GetConnectionString(ConnectionName);

            if (string.IsNullOrEmpty(ConnectionString))
                throw new NLogConfigurationException("Can not resolve MongoDB ConnectionString. Please make sure the ConnectionString property is set.");

            var mongoServers = GetDbServerAddress(ConnectionString, ReplicaSetName, out replicaSet);
            var mongoSettings = new MongoClientSettings
            {
                Servers = mongoServers,
                UseSsl = false,
                ConnectionMode = ConnectionMode.Automatic,
                ApplicationName = "NLog.Mongo"
            };

            if (UseSsl)
            {
                var cert = new X509Certificate2(ClientCertPfx, ClientCertPassword);
                var sslSetting = new SslSettings
                {
                    ClientCertificates = new[] { cert },
                    CheckCertificateRevocation = true,
                    ServerCertificateValidationCallback = (sender, certificate, chain, errors) => true,
                    ClientCertificateSelectionCallback = (sender, host, certificates, certificate, issuers) => cert
                };
                mongoSettings.UseSsl = true;
                mongoSettings.VerifySslCertificate = true;
                mongoSettings.SslSettings = sslSetting;
            }

            if (replicaSet != string.Empty)
            {
                mongoSettings.ReplicaSetName = replicaSet;
                mongoSettings.ConnectionMode = ConnectionMode.ReplicaSet;
            }

            if (UseAuth && UserName != string.Empty)
                mongoSettings.Credentials = UseX509
                    ? new[] { MongoCredential.CreateMongoX509Credential(UserName) }
                    : new[] { MongoCredential.CreateCredential(AuthDatabase, UserName, UserPassword) };

            var dbClient = new MongoClient(mongoSettings);
            _mongoDatabase = dbClient.GetDatabase(DatabaseName ?? "NLog");

        }

        /// <summary>
        /// Writes an array of logging events to the log target. By default it iterates on all
        /// events and passes them to "Write" method. Inheriting classes can use this method to
        /// optimize batch writes.
        /// </summary>
        /// <param name="logEvents">Logging events to be written out.</param>
        protected override void Write(AsyncLogEventInfo[] logEvents)
        {
            if (logEvents.Length == 0)
                return;

            try
            {
                var documents = logEvents.Select(e => CreateDocument(e.LogEvent));

                var collection = GetCollection();
                collection.InsertMany(documents);

                foreach (var ev in logEvents)
                    ev.Continuation(null);

            }
            catch (Exception ex)
            {
                if (ex is StackOverflowException || ex is ThreadAbortException || ex is OutOfMemoryException || ex is NLogConfigurationException)
                    throw;

                InternalLogger.Error("Error when writing to MongoDB {0}", ex);

                foreach (var ev in logEvents)
                    ev.Continuation(ex);

            }
        }

        /// <summary>
        /// Writes logging event to the log target.
        /// classes.
        /// </summary>
        /// <param name="logEvent">Logging event to be written out.</param>
        protected override void Write(LogEventInfo logEvent)
        {
            try
            {
                var document = CreateDocument(logEvent);
                var collection = GetCollection();
                collection.InsertOne(document);
            }
            catch (Exception ex)
            {
                if (ex is StackOverflowException || ex is ThreadAbortException || ex is OutOfMemoryException || ex is NLogConfigurationException)
                    throw;

                InternalLogger.Error("Error when writing to MongoDB {0}", ex);
            }
        }


        #region Private Method Section

        private BsonDocument CreateDocument(LogEventInfo logEvent)
        {
            var document = new BsonDocument();
            if (IncludeDefaults || Fields.Count == 0)
                AddDefaults(document, logEvent);

            // extra fields
            foreach (var field in Fields)
            {
                var value = GetValue(field, logEvent);
                if (value != null)
                    document[field.Name] = value;
            }

            AddProperties(document, logEvent);

            return document;
        }

        private void AddDefaults(BsonDocument document, LogEventInfo logEvent)
        {
            document.Add("Date", new BsonDateTime(logEvent.TimeStamp));

            if (logEvent.Level != null)
                document.Add("Level", new BsonString(logEvent.Level.Name));

            if (logEvent.LoggerName != null)
                document.Add("Logger", new BsonString(logEvent.LoggerName));

            if (logEvent.FormattedMessage != null)
                document.Add("Message", new BsonString(logEvent.FormattedMessage));

            if (logEvent.Exception != null)
                document.Add("Exception", CreateException(logEvent.Exception));


        }

        private void AddProperties(BsonDocument document, LogEventInfo logEvent)
        {
            var propertiesDocument = new BsonDocument();
            foreach (var field in Properties)
            {
                string key = field.Name;
                var value = GetValue(field, logEvent);

                if (value != null)
                    propertiesDocument[key] = value;
            }

            var properties = logEvent.Properties ?? Enumerable.Empty<KeyValuePair<object, object>>();
            foreach (var property in properties)
            {
                if (property.Key == null || property.Value == null)
                    continue;

                string key = Convert.ToString(property.Key, CultureInfo.InvariantCulture);
                string value = Convert.ToString(property.Value, CultureInfo.InvariantCulture);

                if (!string.IsNullOrEmpty(value))
                    propertiesDocument[key] = new BsonString(value);
            }

            if (propertiesDocument.ElementCount > 0)
                document.Add("Properties", propertiesDocument);

        }

        private BsonValue CreateException(Exception exception)
        {
            if (exception == null)
                return BsonNull.Value;

            var document = new BsonDocument();
            document.Add("Message", new BsonString(exception.Message));
            document.Add("BaseMessage", new BsonString(exception.GetBaseException().Message));
            document.Add("Text", new BsonString(exception.ToString()));
            document.Add("Type", new BsonString(exception.GetType().ToString()));

            var external = exception as ExternalException;
            if (external != null)
                document.Add("ErrorCode", new BsonInt32(external.ErrorCode));

            document.Add("Source", new BsonString(exception.Source));

            MethodBase method = exception.TargetSite;
            if (method != null)
            {
                document.Add("MethodName", new BsonString(method.Name));

                AssemblyName assembly = method.Module.Assembly.GetName();
                document.Add("ModuleName", new BsonString(assembly.Name));
                document.Add("ModuleVersion", new BsonString(assembly.Version.ToString()));
            }

            return document;
        }

        private BsonValue GetValue(MongoField field, LogEventInfo logEvent)
        {
            var value = field.Layout.Render(logEvent);
            if (string.IsNullOrWhiteSpace(value))
                return null;

            value = value.Trim();
            
            if (string.IsNullOrEmpty(field.BsonType) 
                || string.Equals(field.BsonType, "String", StringComparison.OrdinalIgnoreCase))
                return new BsonString(value);

            
            BsonValue bsonValue;
            if (string.Equals(field.BsonType, "Boolean", StringComparison.OrdinalIgnoreCase)
                && MongoConvert.TryBoolean(value, out bsonValue))
                return bsonValue;

            if (string.Equals(field.BsonType, "DateTime", StringComparison.OrdinalIgnoreCase)
                && MongoConvert.TryDateTime(value, out bsonValue))
                return bsonValue;

            if (string.Equals(field.BsonType, "Double", StringComparison.OrdinalIgnoreCase)
                && MongoConvert.TryDouble(value, out bsonValue))
                return bsonValue;
            
            if (string.Equals(field.BsonType, "Int32", StringComparison.OrdinalIgnoreCase)
                && MongoConvert.TryInt32(value, out bsonValue))
                return bsonValue;
            
            if (string.Equals(field.BsonType, "Int64", StringComparison.OrdinalIgnoreCase)
                && MongoConvert.TryInt64(value, out bsonValue))
                return bsonValue;

            return new BsonString(value);
        }

        private static async Task<bool> CollectionExistsAsync(string collectionName)
        {
            var filter = new BsonDocument("name", collectionName);
            //filter by collection name
            var collections = await _mongoDatabase.ListCollectionsAsync(new ListCollectionsOptions { Filter = filter });
            //check for existence
            return await collections.AnyAsync();
        }

        private IMongoCollection<BsonDocument> GetCollection()
        {
            // cache mongo collection based on target name.
            var key = string.Format("k|{0}|{1}|{2}", 
                ConnectionName ?? string.Empty, 
                ConnectionString ?? string.Empty, 
                CollectionName ?? string.Empty);

            return CollectionCache.GetOrAdd(key, k =>
            {
                // create collection
//                var mongoUrl = new MongoUrl(ConnectionString);
//                var client = new MongoClient(mongoUrl);
////                var server = client.GetServer();
//                _mongoDatabase = client.GetDatabase(DatabaseName ?? "NLog");
                var collectionName = CollectionName ?? "Log";

                if (!CappedCollectionSize.HasValue || CollectionExistsAsync(collectionName).Result)
                    return _mongoDatabase.GetCollection<BsonDocument>(collectionName);
                var options = new CreateCollectionOptions
                {
                    Capped = true,
                    MaxSize = CappedCollectionSize ?? 26214400
                };
                if (CappedCollectionMaxItems.HasValue) options.MaxDocuments = CappedCollectionMaxItems;

                _mongoDatabase.CreateCollection(collectionName, options);

                return _mongoDatabase.GetCollection<BsonDocument>(collectionName);
            });
        }


//        private static string GetConnectionString(string connectionName)
//        {
//            if (connectionName == null)
//                throw new ArgumentNullException("connectionName");
//
//            var settings = ConfigurationManager.ConnectionStrings[connectionName];
//            if (settings == null)
//                throw new NLogConfigurationException(
//                    $"No connection string named '{connectionName}' could be found in the application configuration file.");
//
//            var connectionString = settings.ConnectionString;
//            if (string.IsNullOrEmpty(connectionString))
//                throw new NLogConfigurationException(
//                    $"The connection string '{connectionName}' in the application's configuration file does not contain the required connectionString attribute.");
//
//            return settings.ConnectionString;
//        }

        private static IEnumerable<MongoServerAddress> GetDbServerAddress(string connectionString, string replicaSetIn, out string replicaSet)
        {
            if (connectionString == string.Empty)
            {
                replicaSet = "";
                return null;
            }

            var split1 = connectionString.Split('/');
            var addrList = split1[0] == "mongodb:" ? split1[2] : connectionString;

            var rSplit = connectionString.Split('=');
            replicaSet = rSplit.Length == 2 ? rSplit[1] : replicaSetIn;

            var result = (from c in addrList.Split(',')
                select c.Split(':')
                into cSplit
                let addr = cSplit[0]
                let port = cSplit.Length == 2 ? Convert.ToInt32(cSplit[1]) : 27017
                select new MongoServerAddress(addr, port)).ToList();

            return result;
        }
        #endregion

    }
}
