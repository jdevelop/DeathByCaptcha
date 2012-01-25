-- | Implementation of captcha recognition using <http://www.deathbycaptcha.com> service
module DeathByCaptcha.Captcha ( 
    TCaptcha(..),
    pngCaptcha,
    jpgCaptcha,
    gifCaptcha,
    Filepath,
    mkFilePath,
    TError(..),
    Response(..),
    Recognizable(..)
) where

import Control.Monad
import Network.Curl
import Data.Maybe
import Text.Regex.PCRE
import System.Posix.Unistd
import System.Directory
import System.FilePath
import System.Random
import Codec.Binary.Url
import qualified Data.ByteString.Char8 as BS
import qualified Data.Map as DM

{-|
    Declares data structure to be used as source of captcha.
 -}
data TCaptcha a = Captcha {
    username, password :: String, -- ^ username and password
    captcha :: a, -- ^ captcha source
    mimeType :: String -- ^ MIME type of captcha source (image/png etc)
    }

-- | makes instance of PNG captcha
pngCaptcha ::  String -- ^ username
                -> String -- ^ password
                -> a -- ^ captcha
                -> TCaptcha a  -- ^ captcha
pngCaptcha user paswd cptch  = Captcha user paswd cptch "image/png" 


-- | makes instance of JPG captcha
jpgCaptcha ::  String -- ^ username
                -> String -- ^ password
                -> a -- ^ captcha
                -> TCaptcha a  -- ^ captcha
jpgCaptcha user paswd cptch  = Captcha user paswd cptch "image/jpeg" 


-- | makes instance of GIF captcha
gifCaptcha ::  String -- ^ username
                -> String -- ^ password
                -> a -- ^ captcha
                -> TCaptcha a  -- ^ captcha
gifCaptcha user paswd cptch  = Captcha user paswd cptch "image/gif" 


newtype Filepath = Filepath { getFilepath :: String }

-- | creates Filepath with given String as path on filesystem
mkFilePath ::  String -> Filepath
mkFilePath path = Filepath path

data TError = ServerError | -- ^ internal server error, something is wrong with website
              BadRequest | -- ^ the request was not built properly. Pls send me details or patch.
              Forbidden | -- ^ wrong credentials or your balance is zero.
              ServiceDown | -- ^ they are overloaded with lots of captchas to recognize. Pls wait.
              ParseError String | -- ^ something wrong with parsing header of captcha status link or with parsing captcha status itself.
              MissingHeader | -- ^ service didn't return link to captcha status.
              Timeout | -- ^ they didn't parse captcha in given time.
              WrongCaptcha Int String | -- ^ unable to parse captcha status.
              Unknown Int -- ^ wrong HTTP status code returned by server.
                deriving (Show)

errorMap = DM.fromList [
    (500,ServerError),
    (400,BadRequest),
    (403,Forbidden),
    (503,ServiceDown)
    ]

type LocalCtx = ( String, String, String, [String] )

-- | Defines result of parsing the captcha. Left contains an error, Right - parsed text.
type Response = Either TError String

{-|
    Typeclass which applies recognize method to given captcha. Only file and bytestrings are supported for now.
-}
class Recognizable a where
    -- | takes passed captcha and returns string from it or an error
    recognize :: Int  -- ^ Number of retries for getting status before raising an error
                -> Int -- ^ Number of seconds to wait between tries
                -> TCaptcha a -- ^ captcha to recognize
                -> IO Response -- ^ captcha recognition response

instance Recognizable Filepath
    where
        recognize tries delay c = do
            curl <- initialize
            withCurlDo $
                wait curl tries . buildResult . extract =<< do_curl_ curl "http://api.deathbycaptcha.com/api/captcha" 
                        [
                            CurlVerbose False, 
                            CurlHttpHeaders [
                                "Expect: "
                                ],
                            CurlHttpPost postData
                        ]
            where
                postData = [
                    HttpPost "captchafile" 
                        (Just (mimeType c))
                        ( ContentFile (getFilepath $ captcha c)) 
                        []
                        Nothing,
                    makeFormPost "username" (username c),
                    makeFormPost "password" (password c)
                    ]
                makeFormPost name value = HttpPost name Nothing
                    (ContentString value)
                    []
                    Nothing
                extract :: CurlResponse_ [(String,String)] BS.ByteString -> (Int, Maybe String)
                extract resp = let code = respStatus resp
                                   result = map snd . filter ((== "Location") . fst) $ respHeaders resp
                               in (code, listToMaybe result)
                buildResult (_, Nothing) = Left MissingHeader
                buildResult (code, Just (location)) | code == 303 = processLocation location
                                                    | otherwise = Left $ DM.findWithDefault (Unknown code) code errorMap
                processLocation loc = match loc (loc =~ "^\\s*http://api.deathbycaptcha.com/api/captcha/(.+)$" :: LocalCtx) 
                match s (_,_,_,[key]) = Right key
                match s _ = Left $ ParseError s
                wait _ 0 _ = return $ Left Timeout
                wait _ _ a@(Left e) = return a
                wait curl n a@(Right code) = do
                    resp <- do_curl_ curl ("http://api.deathbycaptcha.com/api/captcha/"++code)
                        [CurlPost False] :: IO (CurlResponse_ [(String,String)] String)
                    let status = respStatus resp
                    let content = respBody resp
                    if status /= 200 
                        then return (Left $ WrongCaptcha status (code++ " => "++ content)) 
                        else go content
                    where
                        go res = let r = match res (res =~ "text=([^&]*)&?" :: LocalCtx)
                                     f = sleep delay >> wait curl (pred n) a
                                 in case r of 
                                    (Right txt) -> if (txt /= "")
                                                      then return . Right . map (toEnum . fromIntegral) . fromJust . decode $ txt
                                                      else f
                                    otherwise -> f

instance Recognizable BS.ByteString
    where
        recognize tries delay c = do
           tmpDir <- getTemporaryDirectory
           v <- liftM show (randomIO :: IO Int)
           let fileName = tmpDir </> ( "dbc_tmp_" ++ v )
           BS.writeFile fileName ( captcha c )
           z <- recognize tries delay $ Captcha (username c) (password c) (mkFilePath fileName) (mimeType c)
           removeFile fileName
           return z
