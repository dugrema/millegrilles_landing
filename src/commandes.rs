use std::error::Error;
use log::debug;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::GenerateurMessages;
use millegrilles_common_rust::middleware::{ChiffrageFactoryTrait, sauvegarder_traiter_transaction};
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, MongoDao};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::common::*;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireLanding;

pub async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
                                   -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage + ValidateurX509 + ChiffrageFactoryTrait
{
    debug!("consommer_commande : {:?}", &m.message);

    let user_id = m.get_user_id();
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);

    if role_prive && user_id.is_some() {
        // Ok, commande usager
    } else {
        match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
            true => Ok(()),
            false => {
                // Verifier si on a un certificat delegation globale
                match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                    true => Ok(()),
                    false => Err(format!("grosfichiers.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
                }
            }
        }?;
    }

    match m.action.as_str() {
        // Commandes

        // Transactions
        TRANSACTION_CREER_NOUVELLE_APPLICATION => commande_creer_nouvelle_application(middleware, m, gestionnaire).await,
        TRANSACTION_SAUVEGARDER_APPLICATION => commande_sauvegarder_application(middleware, m, gestionnaire).await,

        // Commandes inconnues
        _ => Err(format!("core_backup.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

async fn commande_creer_nouvelle_application<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_creer_nouvelle_application Consommer commande : {:?}", & m.message);
    let commande: TransactionCreerNouvelleApplication = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => Err(format!("commande_creer_nouvelle_application User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_creer_nouvelle_application: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn commande_sauvegarder_application<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + ValidateurX509
{
    debug!("commande_sauvegarder_application Consommer commande : {:?}", & m.message);
    let commande: TransactionSauvegarderApplication = m.message.get_msg().map_contenu(None)?;

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => Err(format!("commande_creer_nouvelle_application User_id absent du certificat"))?
    };

    // Autorisation: Action usager avec compte prive ou delegation globale
    let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
    if role_prive {
        // Ok
    } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
        // Ok
    } else {
        Err(format!("commandes.commande_creer_nouvelle_application: Commande autorisation invalide pour message {:?}", m.correlation_id))?
    }

    // Traiter la transaction
    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

// async fn commande_sauvegader_groupe<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + ValidateurX509
// {
//     debug!("commande_sauvegader_groupe Consommer commande : {:?}", & m.message);
//     let commande: TransactionSauvegarderGroupeUsager = m.message.get_msg().map_contenu(None)?;
//
//     let user_id = match m.get_user_id() {
//         Some(inner) => inner,
//         None => Err(format!("commande_sauvegader_groupe User_id absent du certificat"))?
//     };
//
//     // Autorisation: Action usager avec compte prive ou delegation globale
//     let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
//     if role_prive {
//         // Ok
//     } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//         // Ok
//     } else {
//         Err(format!("commandes.commande_sauvegader_groupe: Commande autorisation invalide pour message {:?}", m.correlation_id))?
//     }
//
//     // S'assurer qu'il n'y a pas de conflit de version pour la categorie
//     if let Some(groupe_id) = &commande.groupe_id {
//         let filtre = doc! { "groupe_id": groupe_id, "user_id": &user_id };
//         let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
//         let doc_groupe_option = collection.find_one(filtre, None).await?;
//         if let Some(groupe) = doc_groupe_option {
//             let doc_groupe: DocGroupeUsager = convertir_bson_deserializable(groupe)?;
//             if doc_groupe.categorie_id != commande.categorie_id {
//                 let reponse = json!({"ok": false, "err": "La categorie ne peut pas etre changee"});
//                 return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
//             }
//         }
//     }
//
//     // Traiter la transaction
//     Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
// }
//
// async fn commande_sauvegader_document<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao + ValidateurX509
// {
//     debug!("commande_sauvegader_document Consommer commande : {:?}", & m.message);
//     let commande: TransactionSauvegarderDocument = m.message.get_msg().map_contenu(None)?;
//
//     let user_id = match m.get_user_id() {
//         Some(inner) => inner,
//         None => Err(format!("commande_sauvegader_groupe User_id absent du certificat"))?
//     };
//
//     // Autorisation: Action usager avec compte prive ou delegation globale
//     let role_prive = m.verifier_roles(vec![RolesCertificats::ComptePrive]);
//     if role_prive {
//         // Ok
//     } else if m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
//         // Ok
//     } else {
//         Err(format!("commandes.commande_sauvegader_document: Commande autorisation invalide pour message {:?}", m.correlation_id))?
//     }
//
//     // S'assurer qu'il n'y a pas de conflit de version pour la categorie
//     if let Some(doc_id) = &commande.doc_id {
//         let filtre = doc! { "doc_id": doc_id, "user_id": &user_id };
//         let collection = middleware.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
//         let doc_option = collection.find_one(filtre, None).await?;
//         if let Some(groupe) = doc_option {
//             let doc_groupe: DocDocument = convertir_bson_deserializable(groupe)?;
//             if doc_groupe.groupe_id != commande.groupe_id {
//                 let reponse = json!({"ok": false, "err": "Le groupe ne peut pas etre changee"});
//                 return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
//             }
//         }
//     }
//
//     // Traiter la transaction
//     Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
// }