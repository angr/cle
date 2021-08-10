class ComponentClass:
    ACTIVITYCLASS = "android.app.Activity"
    SERVICECLASS = "android.app.Service"
    BROADCASTRECEIVERCLASS = "android.content.BroadcastReceiver"
    CONTENTPROVIDERCLASS = "android.content.ContentProvider"
    GCMBASEINTENTSERVICECLASS = "com.google.android.gcm.GCMBaseIntentService"
    GCMLISTENERSERVICECLASS = "com.google.android.gms.gcm.GcmListenerService"
    APPLICATIONCLASS = "android.app.Application"
    FRAGMENTCLASS = "android.app.Fragment"
    SUPPORTFRAGMENTCLASS = "android.support.v4.app.Fragment"
    ANDROIDXFRAGMENTCLASS = "androidx.fragment.app.Fragment"
    SERVICECONNECTIONINTERFACE = "android.content.ServiceConnection"
    MAPACTIVITYCLASS = "com.google.android.maps.MapActivity"

    APPCOMPATACTIVITYCLASS_V4 = "android.support.v4.app.AppCompatActivity"
    APPCOMPATACTIVITYCLASS_V7 = "android.support.v7.app.AppCompatActivity"
    APPCOMPATACTIVITYCLASS_X = "androidx.appcompat.app.AppCompatActivity"

    COMPONENTCALLBACKSINTERFACE = "android.content.ComponentCallbacks"
    COMPONENTCALLBACKS2INTERFACE = "android.content.ComponentCallbacks2"


class ActivityCallback:
    ACTIVITY_ONCREATE = "onCreate(android.os.Bundle)"
    ACTIVITY_ONSTART = "onStart()"
    ACTIVITY_ONRESTOREINSTANCESTATE = "onRestoreInstanceState(android.os.Bundle)"
    ACTIVITY_ONPOSTCREATE = "onPostCreate(android.os.Bundle)"
    ACTIVITY_ONRESUME = "onResume()"
    ACTIVITY_ONPOSTRESUME = "onPostResume()"
    ACTIVITY_ONCREATEDESCRIPTION = "onCreateDescription()"
    ACTIVITY_ONSAVEINSTANCESTATE = "onSaveInstanceState(android.os.Bundle)"
    ACTIVITY_ONPAUSE = "onPause()"
    ACTIVITY_ONSTOP = "onStop()"
    ACTIVITY_ONRESTART = "onRestart()"
    ACTIVITY_ONDESTROY = "onDestroy()"
    ACTIVITY_ONATTACHFRAGMENT = "onAttachFragment(android.app.Fragment)"


class ServiceCallback:
    SERVICE_ONCREATE = "onCreate()"
    SERVICE_ONSTART1 = "onStart(android.content.Intent,int)"
    SERVICE_ONSTART2 = "onStartCommand(android.content.Intent,int,int)"
    SERVICE_ONBIND = "onBind(android.content.Intent)"
    SERVICE_ONREBIND = "onRebind(android.content.Intent)"
    SERVICE_ONUNBIND = "onUnbind(android.content.Intent)"
    SERVICE_ONDESTROY = "onDestroy()"


class RecieverCallback:
    BROADCAST_ONRECEIVE = "onReceive(android.content.Context,android.content.Intent)"


class ProviderCallback:
    CONTENTPROVIDER_ONCREATE = "onCreate()"
    CONTENTPROVIDER_INSERT = "insert(android.net.Uri,android.content.ContentValues)"
    CONTENTPROVIDER_QUERY = "android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)"
    CONTENTPROVIDER_UPDATE = "update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])"
    CONTENTPROVIDER_DELETE = "delete(android.net.Uri,java.lang.String,java.lang.String[])"
    CONTENTPROVIDER_GETTYPE = "getType(android.net.Uri)"


class GCMIntentServiceCallback:
    GCMINTENTSERVICE_ONDELETEDMESSAGES = "onDeletedMessages(android.content.Context,int)"
    GCMINTENTSERVICE_ONERROR = "onError(android.content.Context,java.lang.String)"
    GCMINTENTSERVICE_ONMESSAGE = "onMessage(android.content.Context,android.content.Intent)"
    GCMINTENTSERVICE_ONRECOVERABLEERROR = "onRecoverableError(android.content.Context,java.lang.String)"
    GCMINTENTSERVICE_ONREGISTERED = "onRegistered(android.content.Context,java.lang.String)"
    GCMINTENTSERVICE_ONUNREGISTERED = "onUnregistered(android.content.Context,java.lang.String)"


class GCMListenerServiceCallback:
    GCMLISTENERSERVICE_ONDELETEDMESSAGES = "onDeletedMessages()"
    GCMLISTENERSERVICE_ONMESSAGERECEIVED = "onMessageReceived(java.lang.String,android.os.Bundle)"
    GCMLISTENERSERVICE_ONMESSAGESENT = "onMessageSent(java.lang.String)"
    GCMLISTENERSERVICE_ONSENDERROR = "onSendError(java.lang.String,java.lang.String)"


class ApplicationCallback:
    APPLICATION_ONCREATE = "onCreate()"
    APPLICATION_ONTERMINATE = "onTerminate()"

    SERVICECONNECTION_ONSERVICECONNECTED = "onServiceConnected(android.content.ComponentName,android.os.IBinder)"
    SERVICECONNECTION_ONSERVICEDISCONNECTED = "onServiceDisconnected(android.content.ComponentName)"

    ACTIVITYLIFECYCLECALLBACKSINTERFACE = "android.app.Application$ActivityLifecycleCallbacks"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYSTARTED = "onActivityStarted(android.app.Activity)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYSTOPPED = "onActivityStopped(android.app.Activity)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYSAVEINSTANCESTATE = "onActivitySaveInstanceState(android.app.Activity,android.os.Bundle)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYRESUMED = "onActivityResumed(android.app.Activity)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYPAUSED = "onActivityPaused(android.app.Activity)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYDESTROYED = "onActivityDestroyed(android.app.Activity)"
    ACTIVITYLIFECYCLECALLBACK_ONACTIVITYCREATED = "onActivityCreated(android.app.Activity,android.os.Bundle)"

    COMPONENTCALLBACKS_ONLOWMEMORY = "onLowMemory()"
    COMPONENTCALLBACKS_ONCONFIGURATIONCHANGED = "onConfigurationChanged(android.content.res.Configuration)"

    COMPONENTCALLBACKS2_ONTRIMMEMORY = "onTrimMemory(int)"


class FragmentCallback:
    FRAGMENT_ONCREATE = "onCreate(android.os.Bundle)"
    FRAGMENT_ONATTACH = "onAttach(android.app.Activity)"
    FRAGMENT_ONCREATEVIEW = "onCreateView(android.view.LayoutInflater,android.view.ViewGroup,android.os.Bundle)"
    FRAGMENT_ONVIEWCREATED = "onViewCreated(android.view.View,android.os.Bundle)"
    FRAGMENT_ONSTART = "onStart()"
    FRAGMENT_ONACTIVITYCREATED = "onActivityCreated(android.os.Bundle)"
    FRAGMENT_ONVIEWSTATERESTORED = "onViewStateRestored(android.app.Activity)"
    FRAGMENT_ONRESUME = "onResume()"
    FRAGMENT_ONPAUSE = "onPause()"
    FRAGMENT_ONSTOP = "onStop()"
    FRAGMENT_ONDESTROYVIEW = "onDestroyView()"
    FRAGMENT_ONDESTROY = "onDestroy()"
    FRAGMENT_ONDETACH = "onDetach()"
    FRAGMENT_ONSAVEINSTANCESTATE = "onSaveInstanceState(android.os.Bundle)"


component_class = ComponentClass
callback = {
    'activity': ActivityCallback,
    'service': ServiceCallback,
    'receiver': RecieverCallback,
    'provider': ProviderCallback,
    'gcmintent': GCMIntentServiceCallback,
    'gcmlistener': GCMListenerServiceCallback,
    'application': ApplicationCallback,
    'fragment': FragmentCallback,
    }
