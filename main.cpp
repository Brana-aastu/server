

#include <iostream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <vector>


#include "./crow/include/crow.h"

#include "base64.h"

#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>


#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iomanip>









std::string host = "localhost";
std::string user = "hanif";
std::string password = "mysqlpassword";





enum Request{
    LOGIN,NEW_SESSION,USER_ID,SUPER_STATUS, ADMIN_ADD, DEPT_ID, ADMIN_EVENT, ADMIN_ART, ADMIN_MEMBERS, ADMIN_REQUESTS, SUPER_ADD, SUPER_REMOVE,SUPER_RESOURCE, SUPER_RESOURCE_ADD, SUPER_DEPARTMENTS, HOME_ARTS, HOME_ART, HOME_REQUEST, HOME_EVENTS
};



int get_last_inserted_id(sql::Statement *stmt){

    sql::ResultSet *result = stmt->executeQuery("SELECT LAST_INSERT_ID()");
    
    if (result->next()) {
        return result->getInt(1);

    }else{
        return -1;
    }

    delete result;

    
};





std::string sign(std::string data){

    std::string secrete_key = "s4heoifh83u42";

    unsigned char* result;

    unsigned int len = EVP_MAX_MD_SIZE;

    result = HMAC(EVP_sha256(), secrete_key.c_str(), secrete_key.length(), (unsigned char*)data.c_str(), data.length(), nullptr, nullptr);

    std::ostringstream oss;
    for (unsigned int i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    }
    return oss.str();


};




bool verify(const std::string hash, const std::string data) {

    if (sign(data) == hash){
        return true;
    };

    return false;
    
};







std::unordered_map<std::string, std::string> query(Request request, std::unordered_map<std::string, std::string> options){

    std::unordered_map<std::string, std::string> message;

    try{
        sql::mysql::MySQL_Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;


        driver = sql::mysql::get_mysql_driver_instance();
        con = driver->connect(host, user, password);
        con->setSchema("brana");

        stmt = con->createStatement();



        ////////////////////////////////////



        
        

        if(LOGIN == request){

            std::ostringstream fstring;

            fstring<<"SELECT id,password,super FROM admins WHERE username='"<<options["username"]<<"'";

            std::string the_query = fstring.str();



            res=stmt->executeQuery(the_query);



            

            if (res->next()){

                std::string the_id, the_password, super;
                
                
                the_id = res->getString("id");
                the_password = res->getString("password");
                super = res->getString("super");
                

                

                if (the_password == options["password"]){
                
                    
                    message["the_id"] = the_id;
                    message["super"] = super;
                    message["status"] = "success";
                    

                }else{
                    message["status"] = "message";
                    message["msg"] = "Incorrect username or password";

                }

            }else{

                message["status"] = "message";
                message["msg"] = "Username not found";
            }


            delete res;
            



        
        }else if(NEW_SESSION == request){
            std::ostringstream fstring;

            fstring<<"INSERT INTO sessions(uid) VALUES("<<options["id"]<<")";

            std::string the_query = fstring.str();
            
            stmt->execute(the_query);
        

            int last_id = get_last_inserted_id(stmt);

            if(last_id == -1){
                message["status"] = "message";
                message["msg"] = "Something went wrong";
            }else{
                message["the_id"] = std::to_string(last_id);
                message["status"] = "success";
            }
            
        }else if(USER_ID == request){

            std::ostringstream fstring;

            fstring<<"SELECT uid FROM sessions WHERE id="<<options["sid"];

            std::string the_query = fstring.str();


            res=stmt->executeQuery(the_query);

            res->next();
            std::string uid = res->getString("uid");

            message["uid"] = uid;

            delete res;



            
        }else if(SUPER_STATUS == request){

            std::ostringstream fstring;

            fstring<<"SELECT super FROM admins WHERE id="<<options["uid"];

            std::string the_query = fstring.str();




            res=stmt->executeQuery(the_query);

            res->next();
            std::string super_stat = res->getString("super");

            message["super_stat"] = super_stat;

            delete res;


        }else if(ADMIN_ADD == request){

            std::string the_query = "INSERT INTO members(fname,mname,lname,did,picture) VALUES(\"" + options["fname"] + "\"," + "\"" +  options["mname"] + "\"," + "\"" + options["lname"] + "\"," + options["did"] + "," + "\"" + options["picture"] + "\")";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(DEPT_ID == request){

            std::string the_query = "SELECT did from members where id = (SELECT mid from admins where id = "+options["uid"] + ")";

            res = stmt->executeQuery(the_query);

            res->next();
            std::string did = res->getString("did");

            message["did"] = did;

            delete res;

        }else if(ADMIN_EVENT == request){

            std::string the_query = "INSERT INTO events(title,place,time,description) VALUES(\"" + options["title"] + "\"," + "\"" +  options["place"] + "\"," + "\"" + options["time"] + "\"," + "\"" + options["description"] + "\")";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(ADMIN_ART == request){
            std::string the_query = "INSERT INTO arts(mid,title,description,image) VALUES(" + options["mid"] + "," + "\"" +  options["title"] + "\"," + "\"" + options["description"] + "\"," + "\"" + options["image"] + "\")";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(ADMIN_MEMBERS == request){
            std::string the_query = "SELECT id,fname,mname,lname,picture from members where did="+options["did"];

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string id = res->getString("id");
                std::string fname = res->getString("fname");
                std::string mname = res->getString("mname");
                std::string lname = res->getString("lname");
                std::string picture = res->getString("picture");

                message[id] = fname+","+mname+","+lname+","+picture;
            };


            delete res;

        }else if(ADMIN_REQUESTS == request){
            std::string the_query = "SELECT id,message,email from requests where did="+options["did"];

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string id = res->getString("id");
                std::string the_message = res->getString("message");
                std::string the_email = res->getString("email");
            

                message[id] = the_email+","+the_message;
            };


            delete res;

        }else if(SUPER_ADD == request){

            std::string the_query = "INSERT INTO admins(mid,username,password) VALUES(" + options["mid"] + "," + "\"" +  options["username"] + "\"," + "\"" + options["password"] + "\")";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(SUPER_REMOVE == request){

            std::string the_query = "DELETE FROM admins WHERE username=\"" + options["username"] + "\"";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(SUPER_RESOURCE == request){
            std::string the_query = "SELECT id,title,amount from resources";

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string id = res->getString("id");
                std::string title = res->getString("title");
                std::string amount = res->getString("amount");
            

                message[id] = title+","+amount;
            };


            delete res;

        }else if(SUPER_RESOURCE_ADD == request){

            std::string the_query = "INSERT INTO resources(title,amount) VALUES(\"" + options["title"] + "\"," +  options["amount"] + ")";

            stmt->execute(the_query);

            message["status"] = "success";

        }else if(SUPER_DEPARTMENTS == request){
            std::string the_query = "SELECT id,name from departments";

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string id = res->getString("id");
                std::string zname = res->getString("name");
            

                message[id] = zname;
            };


            delete res;

        }else if(HOME_ARTS == request){
            std::string the_query = "SELECT title,image,mid,id from arts";

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string ztitle = res->getString("title");
                std::string zimage = res->getString("image");
                std::string zmid = res->getString("mid");
                std::string zid = res->getString("id");
            

                message[zid] = ztitle+","+zimage+","+zmid;
            };


            delete res;

        }else if(HOME_ART == request){
            std::string the_query = "SELECT mid,title,description,image from arts where id="+options["aid"];

            res = stmt->executeQuery(the_query);

            res->next();

            message["mid"] = res->getString("mid");
            message["title"] = res->getString("title");
            message["description"] = res->getString("description");
            message["image"] = res->getString("image");
        


            delete res;

        }else if(HOME_EVENTS == request){
            std::string the_query = "SELECT id,title,place,time,description from events";

            res = stmt->executeQuery(the_query);

            while(res->next()){
                std::string zid = res->getString("id");
                std::string ztitle = res->getString("title");
                std::string zplace = res->getString("place");
                std::string ztime = res->getString("time");
                std::string zdescription = res->getString("description");
            

                message[zid] = ztitle+","+zplace+","+ztime+","+zdescription;
            };


            delete res;

        }else if(HOME_REQUEST == request){

            std::string the_query = "INSERT INTO requests(did,message,email) VALUES(" + options["did"] + ",\"" +  options["message"] + "\",\"" + options["email"] +"\")";
            
            std::cout<<the_query<<std::endl;
            stmt->execute(the_query);

            message["status"] = "success";

        };

        
        

        // //////////////////////////////////////////

        delete stmt;
        delete con;


        return message;

    }catch (sql::SQLException &e){
        std::cout<<e.what();

        if (e.getErrorCode() == 1062) {
            message["status"] = "message";
            message["msg"] = "username is already taken";
        }else{
            message["status"] = "message";
            message["msg"] = "something went wrong, try again";
        }

        return message;
    };
};







std::string get_super_status(std::string uid){

    return query(SUPER_STATUS,std::unordered_map<std::string, std::string>{{"uid",uid}})["super_stat"];

}








std::map<std::string, std::string> parse_cookies(const std::string& cookie_header) {
    std::map<std::string, std::string> cookies;
    std::istringstream cookie_stream(cookie_header);
    std::string cookie;

    while (std::getline(cookie_stream, cookie, ';')) {
        auto pos = cookie.find('=');
        if (pos != std::string::npos) {
            std::string name = cookie.substr(0, pos);
            std::string value = cookie.substr(pos + 1);
            cookies[name] = value;
        }
    }

    return cookies;
}







struct cookie_parser{
    struct context{
        std::map<std::string, std::string> cookies;
        std::map<std::string, std::string> set_cookies;
        bool set = false;
        std::string super = "0";
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx){
        auto cookie_header = req.get_header_value("Cookie");
        

        if(!cookie_header.empty()){
            try{
                ctx.cookies = parse_cookies(cookie_header);

                auto thedata = crow::json::load(ctx.cookies["data"]);

                crow::json::wvalue data (thedata);


                std::string first = data["signature"].dump();
                std::string second = data["uid"].dump();

                first = first.substr(1, first.length() - 2);
                second = second.substr(1, second.length() - 2);

                bool is_cookie_valid = verify(first,second);
                

                if(is_cookie_valid){
                    ctx.cookies["status"] = "valid";

                    // value of the sid new mehon yalebet
                    std::string the_user_id = query(USER_ID,std::unordered_map<std::string, std::string>{{"sid",second}})["uid"];
                    
                    ctx.cookies["uid"] = the_user_id;

                    // get the super and set it to ctx

                    ctx.super = get_super_status(the_user_id);

                }else{
                    ctx.cookies["status"] = "invalid";
                }
                

            }catch(const std::exception& e){
                ctx.cookies["status"] = "not_compatible";
            }

        }else{
            ctx.cookies["status"] = "empty";
        }
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){
        if (ctx.set){
            for (const auto& cookie : ctx.set_cookies) {
                res.add_header("Set-Cookie", cookie.first + "=" + cookie.second + "; Path=/; HttpOnly");
            }
        }
    }
};








void set_cookie(cookie_parser::context& ctx, const std::string& value, const std::string& signature) {

    // std::unordered_map<std::string, std::string> uid_signature;

    // uid_signature["uid"] = value;
    // uid_signature["signature"] = signature;


    crow::json::wvalue store;

    // for (const auto& pair : uid_signature) {
    //     store[pair.first] = pair.second;
    // };

    store["uid"] = value;
    store["signature"] = signature;

    ctx.set_cookies["data"] = store.dump();

    ctx.set = true;
}




std::string get_cookie(cookie_parser::context& ctx, const std::string& key) {
    if (ctx.cookies.find(key) != ctx.cookies.end()) {
        return ctx.cookies[key];
    }
    return "Cookie not found";
}




















std::unordered_map<std::string, std::string> access(std::string username, std::string password, cookie_parser::context& ctx){

    std::unordered_map<std::string, std::string> options;


    options["username"] = username;
    options["password"] = password;
    
    std::unordered_map<std::string, std::string> json_string;

    
    json_string = query(LOGIN,options);
   


    if (json_string["status"] == "success"){
        
        std::unordered_map<std::string, std::string> session_id;

        ctx.super = json_string["super"];

        session_id = query(NEW_SESSION,std::unordered_map<std::string, std::string>{{"id",json_string["the_id"]}});
        

        set_cookie(ctx, session_id["the_id"], sign(session_id["the_id"]));
   
   
    }

    json_string.erase("the_id");

    return json_string;
    

}






bool checker(std::string checking_mode,crow::response& res, cookie_parser::context& ctx){

    if(ctx.cookies["status"] != "valid"){
        res.write("access denied");
        res.end();

        return false;
    }


    if(checking_mode == "admin"){
        if(ctx.super != "0"){
            res.write("access denied");
            res.end();

            return false;
        }
    }else if(checking_mode == "super"){
        if(ctx.super != "1"){
            res.write("access denied");
            res.end();

            return false;
        }
    }

    return true;


}





void write_to_file(std::string& filename, std::vector<unsigned char>& data) {
    std::ofstream file("members/"+filename, std::ios::binary);
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();


}






int main()
{
    crow::App<cookie_parser> app;




    
    CROW_ROUTE(app, "/")
    .methods(crow::HTTPMethod::GET)
    ([](){
        auto page = crow::mustache::load_text("index.html");
        
        return page;
    });

    
    CROW_ROUTE(app, "/access/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);

        auto json_data = crow::json::load(req.body);

        std::unordered_map<std::string, std::string> query_response;
        
        query_response = access(json_data["username"].s(),json_data["password"].s(), ctx);


        if (query_response["status"] == "success"){

            if(ctx.super == "0"){
                std::cout<<"admin"<<std::endl;
            }

            std::cout<<"super"<<std::endl;

            res.write("testing");
            res.end();

        }else{

            crow::json::wvalue response_data;


            for (const auto& pair : query_response) {
                response_data[pair.first] = pair.second;
            };

            res.write(response_data.dump());
            res.end();

        }


    });





    CROW_ROUTE(app, "/admin/add/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("admin",res,ctx)) return;


        auto json_data = crow::json::load(req.body);

        std::unordered_map<std::string,std::string> options;

        options["fname"] = json_data["fname"].s();
        options["mname"] = json_data["mname"].s();
        options["lname"] = json_data["lname"].s();
        options["did"] = query(DEPT_ID, std::unordered_map<std::string, std::string>{{"uid",ctx.cookies["uid"]}})["did"];
        options["picture"] = json_data["filename"].s();


        std::unordered_map<std::string,std::string> query_response = query(ADMIN_ADD, options);


        std::string filename = json_data["filename"].s();
        std::string base64_image = json_data["picture"].s();


        std::vector<unsigned char> decoded_image = base64_decode(base64_image);

        write_to_file(filename, decoded_image);
            
        
            
        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();

        


    });


    
    CROW_ROUTE(app, "/admin/event/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("admin",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["title"] = json_data["title"].s();
        options["place"] = json_data["place"].s();
        options["time"] = json_data["time"].s();
        options["description"] = json_data["description"].s();



        std::unordered_map<std::string,std::string> query_response = query(ADMIN_EVENT, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/admin/art/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("admin",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["mid"] = json_data["mid"].s();
        options["title"] = json_data["title"].s();
        options["image"] = json_data["image"].s();
        options["description"] = json_data["description"].s();



        std::unordered_map<std::string,std::string> query_response = query(ADMIN_ART, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });






    CROW_ROUTE(app, "/admin/members/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("admin",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        options["did"] = query(DEPT_ID, std::unordered_map<std::string, std::string>{{"uid",ctx.cookies["uid"]}})["did"];

        std::unordered_map<std::string,std::string> query_response = query(ADMIN_MEMBERS, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });




    CROW_ROUTE(app, "/admin/requests/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("admin",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        options["did"] = query(DEPT_ID, std::unordered_map<std::string, std::string>{{"uid",ctx.cookies["uid"]}})["did"];

        std::unordered_map<std::string,std::string> query_response = query(ADMIN_REQUESTS, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/super/add/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("super",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["mid"] = json_data["mid"].s();
        options["username"] = json_data["username"].s();
        options["password"] = json_data["password"].s();


        std::unordered_map<std::string,std::string> query_response = query(SUPER_ADD, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/super/remove/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("super",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["username"] = json_data["username"].s();


        std::unordered_map<std::string,std::string> query_response = query(SUPER_REMOVE, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });






    CROW_ROUTE(app, "/super/resource/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("super",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        std::unordered_map<std::string,std::string> query_response = query(SUPER_RESOURCE, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });






    CROW_ROUTE(app, "/super/resource/add/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("super",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["title"] = json_data["title"].s();
        options["amount"] = json_data["amount"].s();


        std::unordered_map<std::string,std::string> query_response = query(SUPER_RESOURCE_ADD, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/super/departments/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        if(!checker("super",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        std::unordered_map<std::string,std::string> query_response = query(SUPER_DEPARTMENTS, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });






    CROW_ROUTE(app, "/home/")
    .methods(crow::HTTPMethod::GET)
    ([](){
        auto page = crow::mustache::load_text("index.html");
        
        return page;
    });




    CROW_ROUTE(app, "/home/arts/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        // if(!checker("super",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        std::unordered_map<std::string,std::string> query_response = query(HOME_ARTS, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/home/art/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        // if(!checker("super",res,ctx)) return;

        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["aid"] = json_data["id"].s();


        std::unordered_map<std::string,std::string> query_response = query(HOME_ART, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });





    CROW_ROUTE(app, "/home/events/")
    .methods(crow::HTTPMethod::GET)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        // if(!checker("super",res,ctx)) return;



        std::unordered_map<std::string,std::string> options;



        std::unordered_map<std::string,std::string> query_response = query(HOME_EVENTS, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });



    CROW_ROUTE(app, "/home/request/")
    .methods(crow::HTTPMethod::POST)
    ([&app](crow::request& req, crow::response& res){

        auto& ctx = app.get_context<cookie_parser>(req);
        

        // if(!checker("super",res,ctx)) return;


        auto json_data = crow::json::load(req.body);


        std::unordered_map<std::string,std::string> options;

        options["did"] = json_data["did"].s();
        options["email"] = json_data["email"].s();
        options["message"] = json_data["message"].s();


        std::unordered_map<std::string,std::string> query_response = query(HOME_REQUEST, options);


        crow::json::wvalue response_data;

        for (const auto& pair : query_response) {
            response_data[pair.first] = pair.second;
        };

        res.write(response_data.dump());
        res.end();
    });



    app.bindaddr("192.168.122.143").port(18080).multithreaded().run();


    return 0;
}